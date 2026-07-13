package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound                = errors.New("not found")
	ErrValidation              = errors.New("validation failed")
	ErrConflict                = errors.New("version conflict")
	ErrInvalidRelationEndpoint = fmt.Errorf("%w: invalid relation endpoint", ErrValidation)
)

const (
	defaultActionPageSize = 200
	maxActionPageSize     = 500
	maxRetainedActions    = 5000
	maxInventoryOrderSize = 10_000
)

type Store struct {
	db *sql.DB
}

type queryContext interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type Options struct {
	SeedDemo bool
	seedDemo func(context.Context, *sql.Tx) error
}

func New(dbPath string) (*Store, error) {
	return NewWithOptions(dbPath, Options{})
}

func NewWithOptions(dbPath string, options Options) (*Store, error) {
	if err := secureDatabaseDirectory(dbPath); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &Store{db: db}
	if err := store.configure(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := secureDatabaseFile(dbPath); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.checkIntegrity(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.recoverInterruptedActions(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if options.SeedDemo {
		seed := options.seedDemo
		if seed == nil {
			seed = seedDemoData
		}
		if err := store.seedDemoIfEmpty(context.Background(), seed); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if err := store.checkIntegrity(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.checkForeignKeys(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := secureDatabaseFile(dbPath); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) configure(ctx context.Context) error {
	pragmas := []string{
		`PRAGMA foreign_keys = ON;`,
		`PRAGMA busy_timeout = 5000;`,
		`PRAGMA journal_mode = WAL;`,
	}

	for _, statement := range pragmas {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure database: %w", err)
		}
	}

	var foreignKeysEnabled int
	if err := s.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeysEnabled); err != nil {
		return fmt.Errorf("verify database foreign keys: %w", err)
	}
	if foreignKeysEnabled != 1 {
		return errors.New("SQLite foreign key enforcement is disabled")
	}

	return nil
}

func secureDatabaseDirectory(dbPath string) error {
	databasePath, ok := filesystemDatabasePath(dbPath)
	if !ok {
		return nil
	}
	directory := filepath.Clean(filepath.Dir(databasePath))
	if directory == "." || directory == string(os.PathSeparator) || directory == filepath.VolumeName(directory)+string(os.PathSeparator) {
		return nil
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	// #nosec G302 -- directories need execute permission; 0700 is owner-only.
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure database directory: %w", err)
	}
	return nil
}

func secureDatabaseFile(dbPath string) error {
	databasePath, ok := filesystemDatabasePath(dbPath)
	if !ok {
		return nil
	}
	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		if err := os.Chmod(path, 0o600); err != nil {
			if errors.Is(err, os.ErrNotExist) && path != databasePath {
				continue
			}
			return fmt.Errorf("secure database file %s: %w", path, err)
		}
	}
	return nil
}

func filesystemDatabasePath(dbPath string) (string, bool) {
	trimmed := strings.TrimSpace(dbPath)
	if trimmed == "" || trimmed == ":memory:" {
		return "", false
	}
	if !strings.HasPrefix(strings.ToLower(trimmed), "file:") {
		return trimmed, true
	}

	remainder := trimmed[len("file:"):]
	pathPart, rawQuery, _ := strings.Cut(remainder, "?")
	query, err := url.ParseQuery(rawQuery)
	if err != nil || strings.EqualFold(query.Get("mode"), "memory") || pathPart == "" || pathPart == ":memory:" {
		return "", false
	}
	decoded, err := url.PathUnescape(pathPart)
	if err != nil || decoded == "" {
		return "", false
	}
	return filepath.FromSlash(decoded), true
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Ready verifies the lightweight database invariants required to serve API
// traffic. Full integrity checks remain part of startup, not every probe.
func (s *Store) Ready(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping: %w", err)
	}

	var schemaVersion int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&schemaVersion); err != nil {
		return fmt.Errorf("read database schema version: %w", err)
	}
	if schemaVersion != latestSchemaVersion {
		return fmt.Errorf("database schema version %d does not match required version %d", schemaVersion, latestSchemaVersion)
	}

	var foreignKeysEnabled int
	if err := s.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeysEnabled); err != nil {
		return fmt.Errorf("read database foreign-key state: %w", err)
	}
	if foreignKeysEnabled != 1 {
		return errors.New("database foreign-key enforcement is disabled")
	}

	return nil
}

func (s *Store) Snapshot(ctx context.Context) (InventorySnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return InventorySnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()

	devices, err := listDevices(ctx, tx)
	if err != nil {
		return InventorySnapshot{}, err
	}

	networkNodes, err := listNetworkNodes(ctx, tx)
	if err != nil {
		return InventorySnapshot{}, err
	}

	networkSegments, err := listNetworkSegments(ctx, tx)
	if err != nil {
		return InventorySnapshot{}, err
	}

	relations, err := listRelations(ctx, tx)
	if err != nil {
		return InventorySnapshot{}, err
	}

	actions, err := listActionsPage(ctx, tx, defaultActionPageSize, 0)
	if err != nil {
		return InventorySnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return InventorySnapshot{}, err
	}

	return InventorySnapshot{
		Devices:         devices,
		NetworkNodes:    networkNodes,
		NetworkSegments: networkSegments,
		Relations:       relations,
		Actions:         actions,
	}, nil
}

// ReorderInventory atomically assigns displayOrder metadata to a complete
// inventory collection. Every supplied version must still match the database.
func (s *Store) ReorderInventory(ctx context.Context, kind string, items []InventoryOrderItem) error {
	if len(items) > maxInventoryOrderSize {
		return validationError("inventory order exceeds %d items", maxInventoryOrderSize)
	}

	var selectStatement string
	var updateStatement string
	switch kind {
	case "device":
		selectStatement = `SELECT id, version, metadata_json FROM devices`
		updateStatement = `UPDATE devices SET metadata_json = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?`
	case "networkNode":
		selectStatement = `SELECT id, version, metadata_json FROM network_nodes`
		updateStatement = `UPDATE network_nodes SET metadata_json = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?`
	case "networkSegment":
		selectStatement = `SELECT id, version, metadata_json FROM network_segments`
		updateStatement = `UPDATE network_segments SET metadata_json = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?`
	default:
		return validationError("inventory order kind %q is unsupported", kind)
	}

	requested := make(map[string]InventoryOrderItem, len(items))
	for _, item := range items {
		id, err := canonicalReferenceID(item.ID, "inventory order id")
		if err != nil {
			return err
		}
		if item.Version < 1 {
			return validationError("inventory order version must be positive")
		}
		if _, duplicate := requested[id]; duplicate {
			return validationError("inventory order id %q is duplicated", id)
		}
		item.ID = id
		requested[id] = item
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	type storedOrderItem struct {
		version  int64
		metadata map[string]string
	}
	stored := make(map[string]storedOrderItem, len(items))
	rows, err := tx.QueryContext(ctx, selectStatement)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		var version int64
		var metadataJSON string
		if err := rows.Scan(&id, &version, &metadataJSON); err != nil {
			_ = rows.Close()
			return err
		}
		metadata := map[string]string{}
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
			_ = rows.Close()
			return fmt.Errorf("decode %s metadata for ordering: %w", kind, err)
		}
		stored[id] = storedOrderItem{version: version, metadata: metadata}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if len(stored) != len(items) {
		return ErrConflict
	}
	for id, item := range requested {
		current, exists := stored[id]
		if !exists || current.version != item.Version {
			return ErrConflict
		}
	}

	now := time.Now().UTC()
	for index, item := range items {
		current := stored[item.ID]
		current.metadata["displayOrder"] = strconv.Itoa(index)
		metadata, err := canonicalMetadata(current.metadata)
		if err != nil {
			return err
		}
		_, metadataJSON, err := marshalJSONFields(nil, metadata)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, updateStatement, metadataJSON, now, item.ID, item.Version)
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil {
			return err
		} else if affected != 1 {
			return ErrConflict
		}
	}

	return tx.Commit()
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	return listDevices(ctx, s.db)
}

func listDevices(ctx context.Context, query queryContext) ([]Device, error) {
	rows, err := query.QueryContext(ctx, `
		SELECT id, version, name, hostname, role, device_type, ip_address, mac_address, network_segment, status, tags_json, metadata_json, created_at, updated_at
		FROM devices
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]Device, 0)
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}

	sort.SliceStable(devices, func(i, j int) bool {
		return compareDisplayOrder(devices[i].Metadata, devices[j].Metadata, devices[i].Name, devices[j].Name)
	})

	return devices, rows.Err()
}

func (s *Store) AddDevice(ctx context.Context, device Device) (Device, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(device.ID) == "" {
		device.ID = "dev-" + uuid.NewString()
	}
	var err error
	device, err = canonicalizeDevice(device)
	if err != nil {
		return Device{}, err
	}
	device.Version = 1
	device.CreatedAt = now
	device.UpdatedAt = now

	tagsJSON, metadataJSON, err := marshalJSONFields(device.Tags, device.Metadata)
	if err != nil {
		return Device{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := validateDeviceNetworkSegment(ctx, tx, device.NetworkSegment); err != nil {
		return Device{}, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO devices (
			id, version, name, hostname, role, device_type, ip_address, mac_address, network_segment, status, tags_json, metadata_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		device.ID, device.Version, device.Name, device.Hostname, device.Role, device.DeviceType, device.IPAddress, device.MACAddress, device.NetworkSegment, device.Status, tagsJSON, metadataJSON, device.CreatedAt, device.UpdatedAt,
	)
	if err != nil {
		return Device{}, err
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}

	return device, nil
}

func (s *Store) GetDevice(ctx context.Context, id string) (Device, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, version, name, hostname, role, device_type, ip_address, mac_address, network_segment, status, tags_json, metadata_json, created_at, updated_at
		FROM devices
		WHERE id = ?
	`, id)

	device, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}

	return device, err
}

func (s *Store) UpdateDevice(ctx context.Context, device Device) (Device, error) {
	var err error
	device, err = canonicalizeExistingDevice(device)
	if err != nil {
		return Device{}, err
	}
	current, err := s.GetDevice(ctx, device.ID)
	if err != nil {
		return Device{}, err
	}
	if device.Version != current.Version {
		return Device{}, ErrConflict
	}

	device.CreatedAt = current.CreatedAt
	device.UpdatedAt = time.Now().UTC()
	device.Version = current.Version + 1

	tagsJSON, metadataJSON, err := marshalJSONFields(device.Tags, device.Metadata)
	if err != nil {
		return Device{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := validateDeviceNetworkSegment(ctx, tx, device.NetworkSegment); err != nil {
		return Device{}, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE devices
		SET version = ?, name = ?, hostname = ?, role = ?, device_type = ?, ip_address = ?, mac_address = ?, network_segment = ?, status = ?, tags_json = ?, metadata_json = ?, updated_at = ?
		WHERE id = ? AND version = ?
	`, device.Version, device.Name, device.Hostname, device.Role, device.DeviceType, device.IPAddress, device.MACAddress, device.NetworkSegment, device.Status, tagsJSON, metadataJSON, device.UpdatedAt, device.ID, current.Version)
	if err != nil {
		return Device{}, err
	}

	if rows, err := result.RowsAffected(); err != nil {
		return Device{}, err
	} else if rows == 0 {
		return Device{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}

	return device, nil
}

func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	return s.deleteEntity(ctx, "device", id, nil)
}

// DeleteDeviceVersioned deletes a device only when version matches the stored row.
func (s *Store) DeleteDeviceVersioned(ctx context.Context, id string, version int64) error {
	return s.deleteEntity(ctx, "device", id, &version)
}

func (s *Store) ListNetworkNodes(ctx context.Context) ([]NetworkNode, error) {
	return listNetworkNodes(ctx, s.db)
}

func listNetworkNodes(ctx context.Context, query queryContext) ([]NetworkNode, error) {
	rows, err := query.QueryContext(ctx, `
		SELECT id, version, name, node_type, management_ip, mac_address, vendor, model, status, tags_json, metadata_json, created_at, updated_at
		FROM network_nodes
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nodes := make([]NetworkNode, 0)
	for rows.Next() {
		node, err := scanNetworkNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}

	sort.SliceStable(nodes, func(i, j int) bool {
		return compareDisplayOrder(nodes[i].Metadata, nodes[j].Metadata, nodes[i].Name, nodes[j].Name)
	})

	return nodes, rows.Err()
}

func (s *Store) AddNetworkNode(ctx context.Context, node NetworkNode) (NetworkNode, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(node.ID) == "" {
		node.ID = "node-" + uuid.NewString()
	}
	var err error
	node, err = canonicalizeNetworkNode(node)
	if err != nil {
		return NetworkNode{}, err
	}
	node.Version = 1
	node.CreatedAt = now
	node.UpdatedAt = now

	tagsJSON, metadataJSON, err := marshalJSONFields(node.Tags, node.Metadata)
	if err != nil {
		return NetworkNode{}, err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO network_nodes (
			id, version, name, node_type, management_ip, mac_address, vendor, model, status, tags_json, metadata_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		node.ID, node.Version, node.Name, node.NodeType, node.ManagementIP, node.MACAddress, node.Vendor, node.Model, node.Status, tagsJSON, metadataJSON, node.CreatedAt, node.UpdatedAt,
	)
	if err != nil {
		return NetworkNode{}, err
	}

	return node, nil
}

func (s *Store) GetNetworkNode(ctx context.Context, id string) (NetworkNode, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, version, name, node_type, management_ip, mac_address, vendor, model, status, tags_json, metadata_json, created_at, updated_at
		FROM network_nodes
		WHERE id = ?
	`, id)

	node, err := scanNetworkNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return NetworkNode{}, ErrNotFound
	}

	return node, err
}

func (s *Store) UpdateNetworkNode(ctx context.Context, node NetworkNode) (NetworkNode, error) {
	var err error
	node, err = canonicalizeExistingNetworkNode(node)
	if err != nil {
		return NetworkNode{}, err
	}
	current, err := s.GetNetworkNode(ctx, node.ID)
	if err != nil {
		return NetworkNode{}, err
	}
	if node.Version != current.Version {
		return NetworkNode{}, ErrConflict
	}

	node.CreatedAt = current.CreatedAt
	node.UpdatedAt = time.Now().UTC()
	node.Version = current.Version + 1

	tagsJSON, metadataJSON, err := marshalJSONFields(node.Tags, node.Metadata)
	if err != nil {
		return NetworkNode{}, err
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE network_nodes
		SET version = ?, name = ?, node_type = ?, management_ip = ?, mac_address = ?, vendor = ?, model = ?, status = ?, tags_json = ?, metadata_json = ?, updated_at = ?
		WHERE id = ? AND version = ?
	`, node.Version, node.Name, node.NodeType, node.ManagementIP, node.MACAddress, node.Vendor, node.Model, node.Status, tagsJSON, metadataJSON, node.UpdatedAt, node.ID, current.Version)
	if err != nil {
		return NetworkNode{}, err
	}

	if rows, err := result.RowsAffected(); err != nil {
		return NetworkNode{}, err
	} else if rows == 0 {
		return NetworkNode{}, ErrConflict
	}

	return node, nil
}

func (s *Store) DeleteNetworkNode(ctx context.Context, id string) error {
	return s.deleteEntity(ctx, "networkNode", id, nil)
}

// DeleteNetworkNodeVersioned deletes a node only when version matches the stored row.
func (s *Store) DeleteNetworkNodeVersioned(ctx context.Context, id string, version int64) error {
	return s.deleteEntity(ctx, "networkNode", id, &version)
}

func (s *Store) ListNetworkSegments(ctx context.Context) ([]NetworkSegment, error) {
	return listNetworkSegments(ctx, s.db)
}

func listNetworkSegments(ctx context.Context, query queryContext) ([]NetworkSegment, error) {
	rows, err := query.QueryContext(ctx, `
		SELECT id, version, name, segment_type, cidr, vlan_id, gateway_ip, dns_domain, metadata_json, created_at, updated_at
		FROM network_segments
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	segments := make([]NetworkSegment, 0)
	for rows.Next() {
		segment, err := scanNetworkSegment(rows)
		if err != nil {
			return nil, err
		}
		segments = append(segments, segment)
	}

	sort.SliceStable(segments, func(i, j int) bool {
		return compareDisplayOrder(segments[i].Metadata, segments[j].Metadata, segments[i].Name, segments[j].Name)
	})

	return segments, rows.Err()
}

func (s *Store) AddNetworkSegment(ctx context.Context, segment NetworkSegment) (NetworkSegment, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(segment.ID) == "" {
		segment.ID = "segment-" + uuid.NewString()
	}
	var err error
	segment, err = canonicalizeNetworkSegment(segment)
	if err != nil {
		return NetworkSegment{}, err
	}
	segment.Version = 1
	segment.CreatedAt = now
	segment.UpdatedAt = now

	_, metadataJSON, err := marshalJSONFields([]string{}, segment.Metadata)
	if err != nil {
		return NetworkSegment{}, err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO network_segments (
			id, version, name, segment_type, cidr, vlan_id, gateway_ip, dns_domain, metadata_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		segment.ID, segment.Version, segment.Name, segment.SegmentType, segment.CIDR, segment.VLANID, segment.GatewayIP, segment.DNSDomain, metadataJSON, segment.CreatedAt, segment.UpdatedAt,
	)
	if err != nil {
		return NetworkSegment{}, err
	}

	return segment, nil
}

func (s *Store) GetNetworkSegment(ctx context.Context, id string) (NetworkSegment, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, version, name, segment_type, cidr, vlan_id, gateway_ip, dns_domain, metadata_json, created_at, updated_at
		FROM network_segments
		WHERE id = ?
	`, id)

	segment, err := scanNetworkSegment(row)
	if errors.Is(err, sql.ErrNoRows) {
		return NetworkSegment{}, ErrNotFound
	}

	return segment, err
}

func (s *Store) UpdateNetworkSegment(ctx context.Context, segment NetworkSegment) (NetworkSegment, error) {
	var err error
	segment, err = canonicalizeExistingNetworkSegment(segment)
	if err != nil {
		return NetworkSegment{}, err
	}
	current, err := s.GetNetworkSegment(ctx, segment.ID)
	if err != nil {
		return NetworkSegment{}, err
	}
	if segment.Version != current.Version {
		return NetworkSegment{}, ErrConflict
	}

	segment.CreatedAt = current.CreatedAt
	segment.UpdatedAt = time.Now().UTC()
	segment.Version = current.Version + 1

	_, metadataJSON, err := marshalJSONFields([]string{}, segment.Metadata)
	if err != nil {
		return NetworkSegment{}, err
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE network_segments
		SET version = ?, name = ?, segment_type = ?, cidr = ?, vlan_id = ?, gateway_ip = ?, dns_domain = ?, metadata_json = ?, updated_at = ?
		WHERE id = ? AND version = ?
	`, segment.Version, segment.Name, segment.SegmentType, segment.CIDR, segment.VLANID, segment.GatewayIP, segment.DNSDomain, metadataJSON, segment.UpdatedAt, segment.ID, current.Version)
	if err != nil {
		return NetworkSegment{}, err
	}

	if rows, err := result.RowsAffected(); err != nil {
		return NetworkSegment{}, err
	} else if rows == 0 {
		return NetworkSegment{}, ErrConflict
	}

	return segment, nil
}

func (s *Store) DeleteNetworkSegment(ctx context.Context, id string) error {
	return s.deleteEntity(ctx, "networkSegment", id, nil)
}

// DeleteNetworkSegmentVersioned deletes a segment only when version matches the stored row.
func (s *Store) DeleteNetworkSegmentVersioned(ctx context.Context, id string, version int64) error {
	return s.deleteEntity(ctx, "networkSegment", id, &version)
}

func (s *Store) ListRelations(ctx context.Context) ([]Relation, error) {
	return listRelations(ctx, s.db)
}

func listRelations(ctx context.Context, query queryContext) ([]Relation, error) {
	rows, err := query.QueryContext(ctx, `
		SELECT id, version, source_kind, source_id, target_kind, target_id, relation_type, confidence, metadata_json, observed_at
		FROM relations
		ORDER BY observed_at DESC, id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	relations := make([]Relation, 0)
	for rows.Next() {
		relation, err := scanRelation(rows)
		if err != nil {
			return nil, err
		}
		relations = append(relations, relation)
	}

	return relations, rows.Err()
}

func (s *Store) AddRelation(ctx context.Context, relation Relation) (Relation, error) {
	if strings.TrimSpace(relation.ID) == "" {
		relation.ID = "rel-" + uuid.NewString()
	}
	var err error
	relation, err = canonicalizeRelation(relation)
	if err != nil {
		return Relation{}, err
	}
	relation.Version = 1
	relation.ObservedAt = time.Now().UTC()
	_, metadataJSON, err := marshalJSONFields([]string{}, relation.Metadata)
	if err != nil {
		return Relation{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Relation{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := validateRelationEndpoints(ctx, tx, relation); err != nil {
		return Relation{}, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO relations (
			id, version, source_kind, source_id, target_kind, target_id, relation_type, confidence, metadata_json, observed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		relation.ID, relation.Version, relation.SourceKind, relation.SourceID, relation.TargetKind, relation.TargetID, relation.RelationType, relation.Confidence, metadataJSON, relation.ObservedAt,
	)
	if err != nil {
		return Relation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Relation{}, err
	}

	return relation, nil
}

func (s *Store) GetRelation(ctx context.Context, id string) (Relation, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, version, source_kind, source_id, target_kind, target_id, relation_type, confidence, metadata_json, observed_at
		FROM relations
		WHERE id = ?
	`, id)

	relation, err := scanRelation(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Relation{}, ErrNotFound
	}

	return relation, err
}

func (s *Store) UpdateRelation(ctx context.Context, relation Relation) (Relation, error) {
	var err error
	relation, err = canonicalizeExistingRelation(relation)
	if err != nil {
		return Relation{}, err
	}
	_, metadataJSON, err := marshalJSONFields([]string{}, relation.Metadata)
	if err != nil {
		return Relation{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Relation{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var currentVersion int64
	if err := tx.QueryRowContext(ctx, `SELECT version, observed_at FROM relations WHERE id = ?`, relation.ID).Scan(&currentVersion, &relation.ObservedAt); errors.Is(err, sql.ErrNoRows) {
		return Relation{}, ErrNotFound
	} else if err != nil {
		return Relation{}, err
	}
	if relation.Version != currentVersion {
		return Relation{}, ErrConflict
	}
	if err := validateRelationEndpoints(ctx, tx, relation); err != nil {
		return Relation{}, err
	}
	relation.Version = currentVersion + 1

	result, err := tx.ExecContext(ctx, `
		UPDATE relations
		SET version = ?, source_kind = ?, source_id = ?, target_kind = ?, target_id = ?, relation_type = ?, confidence = ?, metadata_json = ?
		WHERE id = ? AND version = ?
	`, relation.Version, relation.SourceKind, relation.SourceID, relation.TargetKind, relation.TargetID, relation.RelationType, relation.Confidence, metadataJSON, relation.ID, currentVersion)
	if err != nil {
		return Relation{}, err
	}

	if rows, err := result.RowsAffected(); err != nil {
		return Relation{}, err
	} else if rows == 0 {
		return Relation{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Relation{}, err
	}

	return relation, nil
}

func (s *Store) DeleteRelation(ctx context.Context, id string) error {
	return s.deleteRelation(ctx, id, nil)
}

// DeleteRelationVersioned deletes a relation only when version matches the stored row.
func (s *Store) DeleteRelationVersioned(ctx context.Context, id string, version int64) error {
	return s.deleteRelation(ctx, id, &version)
}

func (s *Store) deleteRelation(ctx context.Context, id string, expectedVersion *int64) error {
	if expectedVersion != nil && *expectedVersion < 1 {
		return validationError("relation version must be positive")
	}
	statement := `DELETE FROM relations WHERE id = ?`
	arguments := []any{id}
	if expectedVersion != nil {
		statement += ` AND version = ?`
		arguments = append(arguments, *expectedVersion)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, statement, arguments...)
	if err != nil {
		return err
	}
	if err := requireDeletedRow(result); err == nil {
		return tx.Commit()
	} else if expectedVersion == nil {
		return err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM relations WHERE id = ?)`, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrConflict
	}
	return ErrNotFound
}

func (s *Store) ListActions(ctx context.Context) ([]Action, error) {
	return s.ListActionsPage(ctx, defaultActionPageSize, 0)
}

func (s *Store) ListActionsPage(ctx context.Context, limit int, offset int) ([]Action, error) {
	if limit <= 0 {
		limit = defaultActionPageSize
	}
	if limit > maxActionPageSize {
		limit = maxActionPageSize
	}
	if offset < 0 {
		return nil, errors.New("action offset must not be negative")
	}
	return listActionsPage(ctx, s.db, limit, offset)
}

func listActionsPage(ctx context.Context, query queryContext, limit int, offset int) ([]Action, error) {
	rows, err := query.QueryContext(ctx, `
		SELECT id, device_id, action_type, status, result_summary, metadata_json, started_at, finished_at
		FROM actions
		ORDER BY started_at DESC, id DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	actions := make([]Action, 0)
	for rows.Next() {
		action, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		actions = append(actions, action)
	}

	return actions, rows.Err()
}

func (s *Store) AddAction(ctx context.Context, action Action) (Action, error) {
	if action.StartedAt.IsZero() {
		action.StartedAt = time.Now().UTC()
	}
	var err error
	action, err = canonicalizeAction(action)
	if err != nil {
		return Action{}, err
	}
	if action.Status == "running" && !action.FinishedAt.IsZero() {
		return Action{}, validationError("running actions must not have a finish time")
	}
	if action.Status != "running" && action.FinishedAt.IsZero() {
		return Action{}, validationError("completed and failed actions require a finish time")
	}
	if !action.FinishedAt.IsZero() && action.FinishedAt.Before(action.StartedAt) {
		return Action{}, validationError("action finish time must not precede its start time")
	}
	_, metadataJSON, err := marshalJSONFields(nil, action.Metadata)
	if err != nil {
		return Action{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Action{}, err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO actions (
			id, device_id, action_type, status, result_summary, metadata_json, started_at, finished_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, action.ID, action.DeviceID, action.ActionType, action.Status, action.ResultSummary, metadataJSON, action.StartedAt, action.FinishedAt)
	if err != nil {
		return Action{}, err
	}
	if err := pruneActions(ctx, tx, maxRetainedActions); err != nil {
		return Action{}, err
	}
	if err := tx.Commit(); err != nil {
		return Action{}, err
	}

	return action, nil
}

func pruneActions(ctx context.Context, tx *sql.Tx, retain int) error {
	if retain < 0 {
		return errors.New("action retention must not be negative")
	}
	_, err := tx.ExecContext(ctx, `
		DELETE FROM actions
		WHERE id IN (
			SELECT id FROM actions
			WHERE status <> 'running'
			ORDER BY started_at DESC, id DESC
			LIMIT -1 OFFSET ?
		)
	`, retain)
	return err
}

func (s *Store) UpdateAction(ctx context.Context, action Action) (Action, error) {
	var err error
	action, err = canonicalizeExistingAction(action)
	if err != nil {
		return Action{}, err
	}
	current, err := s.getAction(ctx, action.ID)
	if err != nil {
		return Action{}, err
	}
	if action.DeviceID != current.DeviceID || action.ActionType != current.ActionType || !action.StartedAt.Equal(current.StartedAt) {
		return Action{}, validationError("action device, type, and start time are immutable")
	}
	if current.Status != "running" || (action.Status != "completed" && action.Status != "failed") {
		return Action{}, ErrConflict
	}
	if action.FinishedAt.IsZero() {
		return Action{}, validationError("completed and failed actions require a finish time")
	}
	if action.FinishedAt.Before(action.StartedAt) {
		return Action{}, validationError("action finish time must not precede its start time")
	}
	_, metadataJSON, err := marshalJSONFields(nil, action.Metadata)
	if err != nil {
		return Action{}, err
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE actions
		SET device_id = ?, action_type = ?, status = ?, result_summary = ?,
			metadata_json = ?, started_at = ?, finished_at = ?
		WHERE id = ? AND status = 'running'
	`, action.DeviceID, action.ActionType, action.Status, action.ResultSummary,
		metadataJSON, action.StartedAt, action.FinishedAt, action.ID)
	if err != nil {
		return Action{}, err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return Action{}, err
	} else if rows == 0 {
		return Action{}, ErrConflict
	}
	return action, nil
}

func (s *Store) getAction(ctx context.Context, id string) (Action, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, device_id, action_type, status, result_summary, metadata_json, started_at, finished_at
		FROM actions
		WHERE id = ?
	`, id)
	action, err := scanAction(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Action{}, ErrNotFound
	}
	return action, err
}

func (s *Store) ClearActions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM actions WHERE status <> 'running'`)
	return err
}

func (s *Store) recoverInterruptedActions(ctx context.Context) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		UPDATE actions
		SET status = 'failed',
			result_summary = 'Interrupted by previous process termination.',
			metadata_json = json_set(
				CASE WHEN json_valid(metadata_json) THEN metadata_json ELSE '{}' END,
				'$.terminationReason', 'process_restart'
			),
			finished_at = ?
		WHERE status = 'running'
	`, now)
	if err != nil {
		return fmt.Errorf("recover interrupted actions: %w", err)
	}
	return nil
}

func (s *Store) GetSSHCredential(ctx context.Context, deviceID string) (SSHCredential, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT device_id, username, password_ciphertext, password_nonce, key_version, created_at, updated_at
		FROM ssh_credentials
		WHERE device_id = ?
	`, deviceID)

	credential, err := scanSSHCredential(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SSHCredential{}, ErrNotFound
	}

	return credential, err
}

func (s *Store) ListSSHCredentials(ctx context.Context) ([]SSHCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT device_id, username, password_ciphertext, password_nonce, key_version, created_at, updated_at
		FROM ssh_credentials
		ORDER BY device_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	credentials := make([]SSHCredential, 0)
	for rows.Next() {
		credential, err := scanSSHCredential(rows)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

// DeleteSSHCredentialAndPort removes a stored credential and its device port
// metadata only when the caller still holds the current device version.
func (s *Store) DeleteSSHCredentialAndPort(ctx context.Context, deviceID string, expectedDeviceVersion int64) error {
	deviceID, err := canonicalReferenceID(deviceID, "credential device id")
	if err != nil {
		return err
	}
	if expectedDeviceVersion < 1 {
		return validationError("device version must be positive")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var metadataJSON string
	var currentVersion int64
	if err := tx.QueryRowContext(ctx, `SELECT metadata_json, version FROM devices WHERE id = ?`, deviceID).Scan(&metadataJSON, &currentVersion); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if currentVersion != expectedDeviceVersion {
		return ErrConflict
	}

	result, err := tx.ExecContext(ctx, `DELETE FROM ssh_credentials WHERE device_id = ?`, deviceID)
	if err != nil {
		return err
	}
	if err := requireDeletedRow(result); err != nil {
		return err
	}

	metadata := map[string]string{}
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return fmt.Errorf("decode device metadata for SSH credential deletion: %w", err)
	}
	delete(metadata, "sshPort")
	metadata, err = canonicalMetadata(metadata)
	if err != nil {
		return err
	}
	_, metadataJSON, err = marshalJSONFields(nil, metadata)
	if err != nil {
		return err
	}

	result, err = tx.ExecContext(ctx, `
		UPDATE devices
		SET metadata_json = ?, version = version + 1, updated_at = ?
		WHERE id = ? AND version = ?
	`, metadataJSON, time.Now().UTC(), deviceID, expectedDeviceVersion)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil {
		return err
	} else if affected != 1 {
		return ErrConflict
	}

	return tx.Commit()
}

func (s *Store) UpsertSSHCredential(ctx context.Context, credential SSHCredential) (SSHCredential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SSHCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()

	credential, err = upsertSSHCredential(ctx, tx, credential)
	if err != nil {
		return SSHCredential{}, err
	}
	if err := tx.Commit(); err != nil {
		return SSHCredential{}, err
	}
	return credential, nil
}

func (s *Store) UpsertSSHCredentialAndPort(ctx context.Context, credential SSHCredential, sshPort string) (SSHCredential, error) {
	return s.upsertSSHCredentialAndPort(ctx, credential, sshPort, nil)
}

func (s *Store) UpsertSSHCredentialAndPortVersioned(ctx context.Context, credential SSHCredential, sshPort string, expectedDeviceVersion int64) (SSHCredential, error) {
	if expectedDeviceVersion < 1 {
		return SSHCredential{}, validationError("device version must be positive")
	}
	return s.upsertSSHCredentialAndPort(ctx, credential, sshPort, &expectedDeviceVersion)
}

func (s *Store) upsertSSHCredentialAndPort(ctx context.Context, credential SSHCredential, sshPort string, expectedDeviceVersion *int64) (SSHCredential, error) {
	var err error
	credential, err = canonicalizeSSHCredential(credential)
	if err != nil {
		return SSHCredential{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SSHCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var metadataJSON string
	var deviceVersion int64
	if err := tx.QueryRowContext(ctx, `SELECT metadata_json, version FROM devices WHERE id = ?`, credential.DeviceID).Scan(&metadataJSON, &deviceVersion); errors.Is(err, sql.ErrNoRows) {
		return SSHCredential{}, ErrNotFound
	} else if err != nil {
		return SSHCredential{}, err
	}
	if expectedDeviceVersion != nil && deviceVersion != *expectedDeviceVersion {
		return SSHCredential{}, ErrConflict
	}

	metadata := make(map[string]string)
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return SSHCredential{}, fmt.Errorf("decode device metadata: %w", err)
	}
	if port := strings.TrimSpace(sshPort); port == "" {
		delete(metadata, "sshPort")
	} else {
		port, err = canonicalPort(port)
		if err != nil {
			return SSHCredential{}, err
		}
		metadata["sshPort"] = port
	}
	metadata, err = canonicalMetadata(metadata)
	if err != nil {
		return SSHCredential{}, err
	}
	_, metadataJSON, err = marshalJSONFields(nil, metadata)
	if err != nil {
		return SSHCredential{}, err
	}

	credential, err = upsertSSHCredential(ctx, tx, credential)
	if err != nil {
		return SSHCredential{}, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE devices
		SET metadata_json = ?, updated_at = ?, version = version + 1
		WHERE id = ? AND version = ?
	`, metadataJSON, credential.UpdatedAt, credential.DeviceID, deviceVersion)
	if err != nil {
		return SSHCredential{}, err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return SSHCredential{}, err
	} else if rows == 0 {
		return SSHCredential{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return SSHCredential{}, err
	}
	return credential, nil
}

func upsertSSHCredential(ctx context.Context, tx *sql.Tx, credential SSHCredential) (SSHCredential, error) {
	var err error
	credential, err = canonicalizeSSHCredential(credential)
	if err != nil {
		return SSHCredential{}, err
	}
	var deviceExists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE id = ?)`, credential.DeviceID).Scan(&deviceExists); err != nil {
		return SSHCredential{}, err
	}
	if !deviceExists {
		return SSHCredential{}, ErrNotFound
	}
	now := time.Now().UTC()
	if err := tx.QueryRowContext(ctx, `SELECT created_at FROM ssh_credentials WHERE device_id = ?`, credential.DeviceID).Scan(&credential.CreatedAt); errors.Is(err, sql.ErrNoRows) {
		credential.CreatedAt = now
	} else if err != nil {
		return SSHCredential{}, err
	}
	credential.UpdatedAt = now

	_, err = tx.ExecContext(ctx, `
		INSERT INTO ssh_credentials (
			device_id, username, password_ciphertext, password_nonce, key_version, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET
			username = excluded.username,
			password_ciphertext = excluded.password_ciphertext,
			password_nonce = excluded.password_nonce,
			key_version = excluded.key_version,
			updated_at = excluded.updated_at
	`, credential.DeviceID, credential.Username, credential.PasswordCiphertext, credential.PasswordNonce, credential.KeyVersion, credential.CreatedAt, credential.UpdatedAt)
	if err != nil {
		return SSHCredential{}, err
	}
	return credential, nil
}

func (s *Store) GetAdminAccount(ctx context.Context) (AdminAccount, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, created_at, updated_at
		FROM admin_account
		WHERE id = 1
	`)

	var account AdminAccount
	err := row.Scan(
		&account.ID,
		&account.Username,
		&account.PasswordHash,
		&account.CreatedAt,
		&account.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AdminAccount{}, ErrNotFound
	}

	return account, err
}

func (s *Store) BootstrapAdminAccount(ctx context.Context, username string, passwordHash string) (AdminAccount, error) {
	current, err := s.GetAdminAccount(ctx)
	if err == nil {
		return current, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return AdminAccount{}, err
	}

	now := time.Now().UTC()
	account := AdminAccount{
		ID:           1,
		Username:     strings.TrimSpace(username),
		PasswordHash: passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO admin_account (id, username, password_hash, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?)
	`, account.Username, account.PasswordHash, account.CreatedAt, account.UpdatedAt)
	if err != nil {
		return AdminAccount{}, err
	}

	return account, nil
}

func scanDevice(scanner interface {
	Scan(dest ...any) error
}) (Device, error) {
	var device Device
	var tagsJSON string
	var metadataJSON string

	err := scanner.Scan(
		&device.ID,
		&device.Version,
		&device.Name,
		&device.Hostname,
		&device.Role,
		&device.DeviceType,
		&device.IPAddress,
		&device.MACAddress,
		&device.NetworkSegment,
		&device.Status,
		&tagsJSON,
		&metadataJSON,
		&device.CreatedAt,
		&device.UpdatedAt,
	)
	if err != nil {
		return Device{}, err
	}

	if err := json.Unmarshal([]byte(tagsJSON), &device.Tags); err != nil {
		return Device{}, err
	}
	if err := json.Unmarshal([]byte(metadataJSON), &device.Metadata); err != nil {
		return Device{}, err
	}

	return device, nil
}

func scanNetworkNode(scanner interface {
	Scan(dest ...any) error
}) (NetworkNode, error) {
	var node NetworkNode
	var tagsJSON string
	var metadataJSON string

	err := scanner.Scan(
		&node.ID,
		&node.Version,
		&node.Name,
		&node.NodeType,
		&node.ManagementIP,
		&node.MACAddress,
		&node.Vendor,
		&node.Model,
		&node.Status,
		&tagsJSON,
		&metadataJSON,
		&node.CreatedAt,
		&node.UpdatedAt,
	)
	if err != nil {
		return NetworkNode{}, err
	}

	if err := json.Unmarshal([]byte(tagsJSON), &node.Tags); err != nil {
		return NetworkNode{}, err
	}
	if err := json.Unmarshal([]byte(metadataJSON), &node.Metadata); err != nil {
		return NetworkNode{}, err
	}

	return node, nil
}

func scanNetworkSegment(scanner interface {
	Scan(dest ...any) error
}) (NetworkSegment, error) {
	var segment NetworkSegment
	var metadataJSON string

	err := scanner.Scan(
		&segment.ID,
		&segment.Version,
		&segment.Name,
		&segment.SegmentType,
		&segment.CIDR,
		&segment.VLANID,
		&segment.GatewayIP,
		&segment.DNSDomain,
		&metadataJSON,
		&segment.CreatedAt,
		&segment.UpdatedAt,
	)
	if err != nil {
		return NetworkSegment{}, err
	}

	if err := json.Unmarshal([]byte(metadataJSON), &segment.Metadata); err != nil {
		return NetworkSegment{}, err
	}

	return segment, nil
}

func scanRelation(scanner interface {
	Scan(dest ...any) error
}) (Relation, error) {
	var relation Relation
	var metadataJSON string

	err := scanner.Scan(
		&relation.ID,
		&relation.Version,
		&relation.SourceKind,
		&relation.SourceID,
		&relation.TargetKind,
		&relation.TargetID,
		&relation.RelationType,
		&relation.Confidence,
		&metadataJSON,
		&relation.ObservedAt,
	)
	if err != nil {
		return Relation{}, err
	}

	if err := json.Unmarshal([]byte(metadataJSON), &relation.Metadata); err != nil {
		return Relation{}, err
	}

	return relation, nil
}

func scanAction(scanner interface {
	Scan(dest ...any) error
}) (Action, error) {
	var action Action
	var metadataJSON string

	err := scanner.Scan(
		&action.ID,
		&action.DeviceID,
		&action.ActionType,
		&action.Status,
		&action.ResultSummary,
		&metadataJSON,
		&action.StartedAt,
		&action.FinishedAt,
	)
	if err != nil {
		return Action{}, err
	}

	if err := json.Unmarshal([]byte(metadataJSON), &action.Metadata); err != nil {
		return Action{}, err
	}

	return action, nil
}

func scanSSHCredential(scanner interface {
	Scan(dest ...any) error
}) (SSHCredential, error) {
	var credential SSHCredential

	err := scanner.Scan(
		&credential.DeviceID,
		&credential.Username,
		&credential.PasswordCiphertext,
		&credential.PasswordNonce,
		&credential.KeyVersion,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)
	if err != nil {
		return SSHCredential{}, err
	}

	credential.HasPassword = credential.PasswordCiphertext != ""
	return credential, nil
}

func marshalJSONFields(tags []string, metadata map[string]string) (string, string, error) {
	if tags == nil {
		tags = []string{}
	}
	if metadata == nil {
		metadata = map[string]string{}
	}

	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return "", "", err
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", "", err
	}

	return string(tagsJSON), string(metadataJSON), nil
}

func validateRelationEndpoints(ctx context.Context, tx *sql.Tx, relation Relation) error {
	endpoints := []struct {
		label string
		kind  string
		id    string
	}{
		{label: "source", kind: relation.SourceKind, id: relation.SourceID},
		{label: "target", kind: relation.TargetKind, id: relation.TargetID},
	}

	for _, endpoint := range endpoints {
		if strings.TrimSpace(endpoint.id) == "" {
			return fmt.Errorf("%w: %s ID is empty", ErrInvalidRelationEndpoint, endpoint.label)
		}
		var query string
		switch endpoint.kind {
		case "device":
			query = `SELECT EXISTS(SELECT 1 FROM devices WHERE id = ?)`
		case "networkNode":
			query = `SELECT EXISTS(SELECT 1 FROM network_nodes WHERE id = ?)`
		case "networkSegment":
			query = `SELECT EXISTS(SELECT 1 FROM network_segments WHERE id = ?)`
		default:
			return fmt.Errorf("%w: unsupported %s kind %q", ErrInvalidRelationEndpoint, endpoint.label, endpoint.kind)
		}

		var exists bool
		if err := tx.QueryRowContext(ctx, query, endpoint.id).Scan(&exists); err != nil {
			return fmt.Errorf("validate %s relation endpoint: %w", endpoint.label, err)
		}
		if !exists {
			return fmt.Errorf("%w: %s %s %q does not exist", ErrInvalidRelationEndpoint, endpoint.label, endpoint.kind, endpoint.id)
		}
	}
	return nil
}

func validateDeviceNetworkSegment(ctx context.Context, tx *sql.Tx, segmentID string) error {
	if segmentID == "" {
		return nil
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM network_segments WHERE id = ?)`, segmentID).Scan(&exists); err != nil {
		return fmt.Errorf("validate device network segment: %w", err)
	}
	if !exists {
		return validationError("network segment %q does not exist", segmentID)
	}
	return nil
}

func (s *Store) deleteEntity(ctx context.Context, kind string, id string, expectedVersion *int64) error {
	if expectedVersion != nil && *expectedVersion < 1 {
		return validationError("entity version must be positive")
	}
	var deleteStatement string
	var existsStatement string
	switch kind {
	case "device":
		deleteStatement = `DELETE FROM devices WHERE id = ?`
		existsStatement = `SELECT EXISTS(SELECT 1 FROM devices WHERE id = ?)`
	case "networkNode":
		deleteStatement = `DELETE FROM network_nodes WHERE id = ?`
		existsStatement = `SELECT EXISTS(SELECT 1 FROM network_nodes WHERE id = ?)`
	case "networkSegment":
		deleteStatement = `DELETE FROM network_segments WHERE id = ?`
		existsStatement = `SELECT EXISTS(SELECT 1 FROM network_segments WHERE id = ?)`
	default:
		return fmt.Errorf("unsupported entity kind %q", kind)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	arguments := []any{id}
	if expectedVersion != nil {
		deleteStatement += ` AND version = ?`
		arguments = append(arguments, *expectedVersion)
	}
	result, err := tx.ExecContext(ctx, deleteStatement, arguments...)
	if err != nil {
		return err
	}
	if err := requireDeletedRow(result); err != nil {
		if expectedVersion == nil {
			return err
		}
		var exists bool
		if queryErr := tx.QueryRowContext(ctx, existsStatement, id).Scan(&exists); queryErr != nil {
			return queryErr
		}
		if exists {
			return ErrConflict
		}
		return ErrNotFound
	}
	if kind == "networkSegment" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE devices
			SET network_segment = '', version = version + 1, updated_at = ?
			WHERE network_segment = ?
		`, time.Now().UTC(), id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM relations
		WHERE (source_kind = ? AND source_id = ?)
		   OR (target_kind = ? AND target_id = ?)
	`, kind, id, kind, id); err != nil {
		return err
	}
	return tx.Commit()
}

func requireDeletedRow(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func compareDisplayOrder(left map[string]string, right map[string]string, leftName string, rightName string) bool {
	leftOrder := metadataDisplayOrder(left)
	rightOrder := metadataDisplayOrder(right)
	if leftOrder != rightOrder {
		return leftOrder < rightOrder
	}

	return strings.ToLower(leftName) < strings.ToLower(rightName)
}

func metadataDisplayOrder(metadata map[string]string) int {
	if metadata == nil {
		return 1 << 30
	}

	value := strings.TrimSpace(metadata["displayOrder"])
	if value == "" {
		return 1 << 30
	}

	order, err := strconv.Atoi(value)
	if err != nil {
		return 1 << 30
	}

	return order
}
