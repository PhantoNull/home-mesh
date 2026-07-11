package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	ErrInvalidRelationEndpoint = errors.New("invalid relation endpoint")
)

const (
	defaultActionPageSize = 200
	maxActionPageSize     = 500
	maxRetainedActions    = 5000
)

type Store struct {
	db *sql.DB
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
	if !isFilesystemDatabase(dbPath) {
		return nil
	}
	directory := filepath.Clean(filepath.Dir(dbPath))
	if directory == "." || directory == string(os.PathSeparator) || directory == filepath.VolumeName(directory)+string(os.PathSeparator) {
		return nil
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure database directory: %w", err)
	}
	return nil
}

func secureDatabaseFile(dbPath string) error {
	if !isFilesystemDatabase(dbPath) {
		return nil
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		return fmt.Errorf("secure database file: %w", err)
	}
	return nil
}

func isFilesystemDatabase(dbPath string) bool {
	trimmed := strings.TrimSpace(dbPath)
	return trimmed != "" && trimmed != ":memory:" && !strings.HasPrefix(strings.ToLower(trimmed), "file:")
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Snapshot(ctx context.Context) (InventorySnapshot, error) {
	devices, err := s.ListDevices(ctx)
	if err != nil {
		return InventorySnapshot{}, err
	}

	networkNodes, err := s.ListNetworkNodes(ctx)
	if err != nil {
		return InventorySnapshot{}, err
	}

	networkSegments, err := s.ListNetworkSegments(ctx)
	if err != nil {
		return InventorySnapshot{}, err
	}

	relations, err := s.ListRelations(ctx)
	if err != nil {
		return InventorySnapshot{}, err
	}

	actions, err := s.ListActions(ctx)
	if err != nil {
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

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, hostname, role, device_type, ip_address, mac_address, network_segment, status, tags_json, metadata_json, created_at, updated_at
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
	if strings.TrimSpace(device.Status) == "" {
		device.Status = "unknown"
	}
	device.CreatedAt = now
	device.UpdatedAt = now

	tagsJSON, metadataJSON, err := marshalJSONFields(device.Tags, device.Metadata)
	if err != nil {
		return Device{}, err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO devices (
			id, name, hostname, role, device_type, ip_address, mac_address, network_segment, status, tags_json, metadata_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		device.ID, device.Name, device.Hostname, device.Role, device.DeviceType, device.IPAddress, device.MACAddress, device.NetworkSegment, device.Status, tagsJSON, metadataJSON, device.CreatedAt, device.UpdatedAt,
	)
	if err != nil {
		return Device{}, err
	}

	return device, nil
}

func (s *Store) GetDevice(ctx context.Context, id string) (Device, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, hostname, role, device_type, ip_address, mac_address, network_segment, status, tags_json, metadata_json, created_at, updated_at
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
	current, err := s.GetDevice(ctx, device.ID)
	if err != nil {
		return Device{}, err
	}

	device.CreatedAt = current.CreatedAt
	device.UpdatedAt = time.Now().UTC()

	tagsJSON, metadataJSON, err := marshalJSONFields(device.Tags, device.Metadata)
	if err != nil {
		return Device{}, err
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE devices
		SET name = ?, hostname = ?, role = ?, device_type = ?, ip_address = ?, mac_address = ?, network_segment = ?, status = ?, tags_json = ?, metadata_json = ?, updated_at = ?
		WHERE id = ?
	`, device.Name, device.Hostname, device.Role, device.DeviceType, device.IPAddress, device.MACAddress, device.NetworkSegment, device.Status, tagsJSON, metadataJSON, device.UpdatedAt, device.ID)
	if err != nil {
		return Device{}, err
	}

	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return Device{}, ErrNotFound
	}

	return device, nil
}

func (s *Store) DeleteDevice(ctx context.Context, id string) error {
	return s.deleteEntity(ctx, "device", id)
}

func (s *Store) ListNetworkNodes(ctx context.Context) ([]NetworkNode, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, node_type, management_ip, mac_address, vendor, model, status, tags_json, metadata_json, created_at, updated_at
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
	node.CreatedAt = now
	node.UpdatedAt = now

	tagsJSON, metadataJSON, err := marshalJSONFields(node.Tags, node.Metadata)
	if err != nil {
		return NetworkNode{}, err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO network_nodes (
			id, name, node_type, management_ip, mac_address, vendor, model, status, tags_json, metadata_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		node.ID, node.Name, node.NodeType, node.ManagementIP, node.MACAddress, node.Vendor, node.Model, node.Status, tagsJSON, metadataJSON, node.CreatedAt, node.UpdatedAt,
	)
	if err != nil {
		return NetworkNode{}, err
	}

	return node, nil
}

func (s *Store) GetNetworkNode(ctx context.Context, id string) (NetworkNode, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, node_type, management_ip, mac_address, vendor, model, status, tags_json, metadata_json, created_at, updated_at
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
	current, err := s.GetNetworkNode(ctx, node.ID)
	if err != nil {
		return NetworkNode{}, err
	}

	node.CreatedAt = current.CreatedAt
	node.UpdatedAt = time.Now().UTC()

	tagsJSON, metadataJSON, err := marshalJSONFields(node.Tags, node.Metadata)
	if err != nil {
		return NetworkNode{}, err
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE network_nodes
		SET name = ?, node_type = ?, management_ip = ?, mac_address = ?, vendor = ?, model = ?, status = ?, tags_json = ?, metadata_json = ?, updated_at = ?
		WHERE id = ?
	`, node.Name, node.NodeType, node.ManagementIP, node.MACAddress, node.Vendor, node.Model, node.Status, tagsJSON, metadataJSON, node.UpdatedAt, node.ID)
	if err != nil {
		return NetworkNode{}, err
	}

	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return NetworkNode{}, ErrNotFound
	}

	return node, nil
}

func (s *Store) DeleteNetworkNode(ctx context.Context, id string) error {
	return s.deleteEntity(ctx, "networkNode", id)
}

func (s *Store) ListNetworkSegments(ctx context.Context) ([]NetworkSegment, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, segment_type, cidr, vlan_id, gateway_ip, dns_domain, metadata_json, created_at, updated_at
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
	segment.CreatedAt = now
	segment.UpdatedAt = now

	_, metadataJSON, err := marshalJSONFields([]string{}, segment.Metadata)
	if err != nil {
		return NetworkSegment{}, err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO network_segments (
			id, name, segment_type, cidr, vlan_id, gateway_ip, dns_domain, metadata_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		segment.ID, segment.Name, segment.SegmentType, segment.CIDR, segment.VLANID, segment.GatewayIP, segment.DNSDomain, metadataJSON, segment.CreatedAt, segment.UpdatedAt,
	)
	if err != nil {
		return NetworkSegment{}, err
	}

	return segment, nil
}

func (s *Store) GetNetworkSegment(ctx context.Context, id string) (NetworkSegment, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, segment_type, cidr, vlan_id, gateway_ip, dns_domain, metadata_json, created_at, updated_at
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
	current, err := s.GetNetworkSegment(ctx, segment.ID)
	if err != nil {
		return NetworkSegment{}, err
	}

	segment.CreatedAt = current.CreatedAt
	segment.UpdatedAt = time.Now().UTC()

	_, metadataJSON, err := marshalJSONFields([]string{}, segment.Metadata)
	if err != nil {
		return NetworkSegment{}, err
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE network_segments
		SET name = ?, segment_type = ?, cidr = ?, vlan_id = ?, gateway_ip = ?, dns_domain = ?, metadata_json = ?, updated_at = ?
		WHERE id = ?
	`, segment.Name, segment.SegmentType, segment.CIDR, segment.VLANID, segment.GatewayIP, segment.DNSDomain, metadataJSON, segment.UpdatedAt, segment.ID)
	if err != nil {
		return NetworkSegment{}, err
	}

	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return NetworkSegment{}, ErrNotFound
	}

	return segment, nil
}

func (s *Store) DeleteNetworkSegment(ctx context.Context, id string) error {
	return s.deleteEntity(ctx, "networkSegment", id)
}

func (s *Store) ListRelations(ctx context.Context) ([]Relation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, source_kind, source_id, target_kind, target_id, relation_type, confidence, metadata_json, observed_at
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
			id, source_kind, source_id, target_kind, target_id, relation_type, confidence, metadata_json, observed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		relation.ID, relation.SourceKind, relation.SourceID, relation.TargetKind, relation.TargetID, relation.RelationType, relation.Confidence, metadataJSON, relation.ObservedAt,
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
		SELECT id, source_kind, source_id, target_kind, target_id, relation_type, confidence, metadata_json, observed_at
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
	_, metadataJSON, err := marshalJSONFields([]string{}, relation.Metadata)
	if err != nil {
		return Relation{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Relation{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if err := tx.QueryRowContext(ctx, `SELECT observed_at FROM relations WHERE id = ?`, relation.ID).Scan(&relation.ObservedAt); errors.Is(err, sql.ErrNoRows) {
		return Relation{}, ErrNotFound
	} else if err != nil {
		return Relation{}, err
	}
	if err := validateRelationEndpoints(ctx, tx, relation); err != nil {
		return Relation{}, err
	}

	result, err := tx.ExecContext(ctx, `
		UPDATE relations
		SET source_kind = ?, source_id = ?, target_kind = ?, target_id = ?, relation_type = ?, confidence = ?, metadata_json = ?
		WHERE id = ?
	`, relation.SourceKind, relation.SourceID, relation.TargetKind, relation.TargetID, relation.RelationType, relation.Confidence, metadataJSON, relation.ID)
	if err != nil {
		return Relation{}, err
	}

	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return Relation{}, ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return Relation{}, err
	}

	return relation, nil
}

func (s *Store) DeleteRelation(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM relations WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return requireDeletedRow(result)
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
	rows, err := s.db.QueryContext(ctx, `
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
			ORDER BY started_at DESC, id DESC
			LIMIT -1 OFFSET ?
		)
	`, retain)
	return err
}

func (s *Store) UpdateAction(ctx context.Context, action Action) (Action, error) {
	_, metadataJSON, err := marshalJSONFields(nil, action.Metadata)
	if err != nil {
		return Action{}, err
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE actions
		SET device_id = ?, action_type = ?, status = ?, result_summary = ?,
			metadata_json = ?, started_at = ?, finished_at = ?
		WHERE id = ?
	`, action.DeviceID, action.ActionType, action.Status, action.ResultSummary,
		metadataJSON, action.StartedAt, action.FinishedAt, action.ID)
	if err != nil {
		return Action{}, err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return Action{}, err
	} else if rows == 0 {
		return Action{}, ErrNotFound
	}
	return action, nil
}

func (s *Store) ClearActions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM actions`)
	return err
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SSHCredential{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var metadataJSON string
	if err := tx.QueryRowContext(ctx, `SELECT metadata_json FROM devices WHERE id = ?`, credential.DeviceID).Scan(&metadataJSON); errors.Is(err, sql.ErrNoRows) {
		return SSHCredential{}, ErrNotFound
	} else if err != nil {
		return SSHCredential{}, err
	}

	metadata := make(map[string]string)
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return SSHCredential{}, fmt.Errorf("decode device metadata: %w", err)
	}
	if port := strings.TrimSpace(sshPort); port == "" {
		delete(metadata, "sshPort")
	} else {
		metadata["sshPort"] = port
	}
	_, metadataJSON, err = marshalJSONFields(nil, metadata)
	if err != nil {
		return SSHCredential{}, err
	}

	credential, err = upsertSSHCredential(ctx, tx, credential)
	if err != nil {
		return SSHCredential{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET metadata_json = ?, updated_at = ? WHERE id = ?`, metadataJSON, credential.UpdatedAt, credential.DeviceID); err != nil {
		return SSHCredential{}, err
	}
	if err := tx.Commit(); err != nil {
		return SSHCredential{}, err
	}
	return credential, nil
}

func upsertSSHCredential(ctx context.Context, tx *sql.Tx, credential SSHCredential) (SSHCredential, error) {
	now := time.Now().UTC()
	if err := tx.QueryRowContext(ctx, `SELECT created_at FROM ssh_credentials WHERE device_id = ?`, credential.DeviceID).Scan(&credential.CreatedAt); errors.Is(err, sql.ErrNoRows) {
		credential.CreatedAt = now
	} else if err != nil {
		return SSHCredential{}, err
	}
	credential.UpdatedAt = now
	credential.HasPassword = credential.PasswordCiphertext != ""
	if credential.KeyVersion == 0 {
		credential.KeyVersion = 1
	}

	_, err := tx.ExecContext(ctx, `
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

func (s *Store) deleteEntity(ctx context.Context, kind string, id string) error {
	var deleteStatement string
	switch kind {
	case "device":
		deleteStatement = `DELETE FROM devices WHERE id = ?`
	case "networkNode":
		deleteStatement = `DELETE FROM network_nodes WHERE id = ?`
	case "networkSegment":
		deleteStatement = `DELETE FROM network_segments WHERE id = ?`
	default:
		return fmt.Errorf("unsupported entity kind %q", kind)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.ExecContext(ctx, deleteStatement, id)
	if err != nil {
		return err
	}
	if err := requireDeletedRow(result); err != nil {
		return err
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
