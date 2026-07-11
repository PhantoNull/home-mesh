package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

func TestFreshDatabaseMigratesWithoutDefaultSeed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "data", "home-mesh.db")
	store := openTestStore(t, dbPath, Options{})

	var version int
	if err := store.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if version != latestSchemaVersion {
		t.Fatalf("got schema version %d want %d", version, latestSchemaVersion)
	}

	for _, table := range []string{"devices", "network_nodes", "network_segments", "relations", "actions", "ssh_credentials", "ssh_credentials_quarantine", "admin_account"} {
		if !tableExists(t, store.db, table) {
			t.Fatalf("expected migrated table %q", table)
		}
	}

	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("load empty snapshot: %v", err)
	}
	if len(snapshot.Devices)+len(snapshot.NetworkNodes)+len(snapshot.NetworkSegments)+len(snapshot.Relations)+len(snapshot.Actions) != 0 {
		t.Fatalf("New unexpectedly seeded demo data: %+v", snapshot)
	}
}

func TestLegacyVersionZeroDatabaseMigratesInPlace(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	legacy := createLegacyDatabase(t, dbPath)
	now := time.Now().UTC()
	if _, err := legacy.Exec(`
		INSERT INTO devices (id, name, created_at, updated_at)
		VALUES ('legacy-device', 'Legacy device', ?, ?)
	`, now, now); err != nil {
		t.Fatalf("insert legacy device: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	store := openTestStore(t, dbPath, Options{})
	device, err := store.GetDevice(context.Background(), "legacy-device")
	if err != nil {
		t.Fatalf("load migrated legacy device: %v", err)
	}
	if device.Name != "Legacy device" {
		t.Fatalf("got device name %q", device.Name)
	}
	var version int
	if err := store.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != latestSchemaVersion {
		t.Fatalf("got schema version %d, error %v", version, err)
	}
}

func TestMigrationIsAtomic(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "atomic.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	err = applyMigration(context.Background(), db, migration{
		version: 1,
		name:    "deliberate failure",
		statements: []string{
			`CREATE TABLE should_roll_back (id INTEGER PRIMARY KEY)`,
			`THIS IS NOT SQL`,
		},
	})
	if err == nil {
		t.Fatal("expected migration failure")
	}
	if tableExists(t, db, "should_roll_back") {
		t.Fatal("failed migration left its table behind")
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 0 {
		t.Fatalf("got user_version %d, error %v", version, err)
	}
}

func TestOrphanSSHCredentialIsQuarantinedWithoutDataLoss(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "orphan.db")
	legacy := createLegacyDatabase(t, dbPath)
	now := time.Now().UTC()
	if _, err := legacy.Exec(`
		INSERT INTO ssh_credentials (
			device_id, username, password_ciphertext, password_nonce,
			key_version, created_at, updated_at
		) VALUES ('missing-device', 'operator', 'encrypted-value', 'nonce-value', 7, ?, ?)
	`, now, now); err != nil {
		t.Fatalf("insert orphan credential: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	store := openTestStore(t, dbPath, Options{})
	var activeCredentials int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM ssh_credentials`).Scan(&activeCredentials); err != nil {
		t.Fatalf("count active credentials: %v", err)
	}
	if activeCredentials != 0 {
		t.Fatalf("got %d active orphan credentials", activeCredentials)
	}

	var username, ciphertext, nonce, reason string
	var keyVersion int
	if err := store.db.QueryRow(`
		SELECT username, password_ciphertext, password_nonce, key_version, quarantine_reason
		FROM ssh_credentials_quarantine WHERE device_id = 'missing-device'
	`).Scan(&username, &ciphertext, &nonce, &keyVersion, &reason); err != nil {
		t.Fatalf("read quarantined credential: %v", err)
	}
	if username != "operator" || ciphertext != "encrypted-value" || nonce != "nonce-value" || keyVersion != 7 || reason != "missing_device" {
		t.Fatalf("quarantined credential changed: username=%q ciphertext=%q nonce=%q version=%d reason=%q", username, ciphertext, nonce, keyVersion, reason)
	}
	if err := store.checkForeignKeys(context.Background()); err != nil {
		t.Fatalf("foreign key check after quarantine: %v", err)
	}
}

func TestMigrationRedactsLegacySSHActionPlaintext(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-action.db")
	legacy := createLegacyDatabase(t, dbPath)
	now := time.Now().UTC()
	if _, err := legacy.Exec(`
		INSERT INTO actions (
			id, device_id, action_type, status, result_summary, metadata_json,
			started_at, finished_at
		) VALUES (?, ?, 'ssh_command', 'completed', ?, ?, ?, ?)
	`, "legacy-action", "device-a", "secret output first line", `{"command":"cat /secret","output":"secret output","address":"192.0.2.1:22"}`, now, now); err != nil {
		t.Fatalf("insert legacy SSH action: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	store := openTestStore(t, dbPath, Options{})
	actions, err := store.ListActions(context.Background())
	if err != nil || len(actions) != 1 {
		t.Fatalf("list migrated actions = %+v, %v", actions, err)
	}
	action := actions[0]
	if action.ResultSummary != "SSH command completed." {
		t.Fatalf("result summary = %q", action.ResultSummary)
	}
	if _, exists := action.Metadata["command"]; exists {
		t.Fatalf("legacy command remains in metadata: %v", action.Metadata)
	}
	if _, exists := action.Metadata["output"]; exists {
		t.Fatalf("legacy output remains in metadata: %v", action.Metadata)
	}
	if action.Metadata["address"] != "192.0.2.1:22" {
		t.Fatalf("non-sensitive metadata was not preserved: %v", action.Metadata)
	}
}

func TestDemoSeedIsOptInAndTransactional(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "seeded.db")
	store := openTestStore(t, dbPath, Options{SeedDemo: true})
	snapshot, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("load seeded snapshot: %v", err)
	}
	if len(snapshot.Devices) != len(seedDevices()) || len(snapshot.NetworkNodes) != len(seedNetworkNodes()) || len(snapshot.NetworkSegments) != len(seedNetworkSegments()) || len(snapshot.Relations) != len(seedRelations()) || len(snapshot.Actions) != len(seedActions()) {
		t.Fatalf("unexpected demo seed counts: %+v", snapshot)
	}
}

func TestDemoSeedRollsBackOnFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "seed-rollback.db")
	_, err := NewWithOptions(dbPath, Options{
		SeedDemo: true,
		seedDemo: func(ctx context.Context, tx *sql.Tx) error {
			now := time.Now().UTC()
			if _, err := tx.ExecContext(ctx, `INSERT INTO devices (id, name, created_at, updated_at) VALUES ('partial', 'Partial', ?, ?)`, now, now); err != nil {
				return err
			}
			return errors.New("deliberate seed failure")
		},
	})
	if err == nil {
		t.Fatal("expected demo seed failure")
	}

	store := openTestStore(t, dbPath, Options{})
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&count); err != nil {
		t.Fatalf("count devices after rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("failed seed left %d devices behind", count)
	}
}

func TestDemoSeedSkipsNonEmptyDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "not-empty.db")
	store := openTestStore(t, dbPath, Options{})
	if _, err := store.AddDevice(context.Background(), Device{ID: "existing", Name: "Existing"}); err != nil {
		t.Fatalf("insert existing device: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	store = openTestStore(t, dbPath, Options{SeedDemo: true})
	devices, err := store.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 1 || devices[0].ID != "existing" {
		t.Fatalf("demo data was added to non-empty database: %+v", devices)
	}
}

func TestGeneratedIDsAreUniqueUnderConcurrency(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "ids.db"), Options{})
	ctx := context.Background()

	type generatedID struct {
		prefix string
		id     string
		err    error
	}
	const perKind = 24
	results := make(chan generatedID, perKind*3)
	var wg sync.WaitGroup
	for i := 0; i < perKind; i++ {
		wg.Add(3)
		go func(index int) {
			defer wg.Done()
			device, err := store.AddDevice(ctx, Device{Name: fmt.Sprintf("device-%d", index)})
			results <- generatedID{prefix: "dev-", id: device.ID, err: err}
		}(i)
		go func(index int) {
			defer wg.Done()
			node, err := store.AddNetworkNode(ctx, NetworkNode{Name: fmt.Sprintf("node-%d", index), NodeType: "switch"})
			results <- generatedID{prefix: "node-", id: node.ID, err: err}
		}(i)
		go func(index int) {
			defer wg.Done()
			segment, err := store.AddNetworkSegment(ctx, NetworkSegment{Name: fmt.Sprintf("segment-%d", index), SegmentType: "lan"})
			results <- generatedID{prefix: "segment-", id: segment.ID, err: err}
		}(i)
	}
	wg.Wait()
	close(results)

	seen := make(map[string]struct{}, perKind*3)
	for result := range results {
		if result.err != nil {
			t.Fatalf("generate %s ID: %v", result.prefix, result.err)
		}
		if !strings.HasPrefix(result.id, result.prefix) {
			t.Fatalf("ID %q does not have prefix %q", result.id, result.prefix)
		}
		if _, err := uuid.Parse(strings.TrimPrefix(result.id, result.prefix)); err != nil {
			t.Fatalf("ID %q does not contain a UUID: %v", result.id, err)
		}
		if _, exists := seen[result.id]; exists {
			t.Fatalf("duplicate generated ID %q", result.id)
		}
		seen[result.id] = struct{}{}
	}
}

func TestRelationEndpointsAreValidatedAndDeletedWithEntity(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "relations.db"), Options{})
	ctx := context.Background()
	device, err := store.AddDevice(ctx, Device{ID: "dev-a", Name: "Device"})
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.AddNetworkNode(ctx, NetworkNode{ID: "node-a", Name: "Node", NodeType: "router"})
	if err != nil {
		t.Fatal(err)
	}
	segment, err := store.AddNetworkSegment(ctx, NetworkSegment{ID: "seg-a", Name: "Segment", SegmentType: "lan"})
	if err != nil {
		t.Fatal(err)
	}

	invalid := []Relation{
		{ID: "bad-kind", SourceKind: "device", SourceID: device.ID, TargetKind: "unknown", TargetID: node.ID},
		{ID: "bad-id", SourceKind: "device", SourceID: "missing", TargetKind: "networkNode", TargetID: node.ID},
	}
	for _, relation := range invalid {
		if _, err := store.AddRelation(ctx, relation); !errors.Is(err, ErrInvalidRelationEndpoint) {
			t.Fatalf("AddRelation(%s) error %v, want ErrInvalidRelationEndpoint", relation.ID, err)
		}
	}

	valid := []Relation{
		{ID: "device-node", SourceKind: "device", SourceID: device.ID, TargetKind: "networkNode", TargetID: node.ID},
		{ID: "segment-device", SourceKind: "networkSegment", SourceID: segment.ID, TargetKind: "device", TargetID: device.ID},
		{ID: "unrelated", SourceKind: "networkNode", SourceID: node.ID, TargetKind: "networkSegment", TargetID: segment.ID},
	}
	for _, relation := range valid {
		if _, err := store.AddRelation(ctx, relation); err != nil {
			t.Fatalf("add valid relation %s: %v", relation.ID, err)
		}
	}

	if err := store.DeleteDevice(ctx, device.ID); err != nil {
		t.Fatalf("delete device: %v", err)
	}
	relations, err := store.ListRelations(ctx)
	if err != nil {
		t.Fatalf("list relations: %v", err)
	}
	if len(relations) != 1 || relations[0].ID != "unrelated" {
		t.Fatalf("unexpected relations after entity delete: %+v", relations)
	}
}

func TestUpsertSSHCredentialAndPortIsAtomic(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "credential.db"), Options{})
	ctx := context.Background()
	device, err := store.AddDevice(ctx, Device{ID: "dev-ssh", Name: "SSH device"})
	if err != nil {
		t.Fatal(err)
	}
	credential := SSHCredential{DeviceID: device.ID, Username: "root", PasswordCiphertext: "cipher", PasswordNonce: "nonce"}
	if _, err := store.UpsertSSHCredentialAndPort(ctx, credential, "2222"); err != nil {
		t.Fatalf("upsert credential and port: %v", err)
	}

	storedCredential, err := store.GetSSHCredential(ctx, device.ID)
	if err != nil || storedCredential.Username != "root" {
		t.Fatalf("stored credential %+v, error %v", storedCredential, err)
	}
	credentials, err := store.ListSSHCredentials(ctx)
	if err != nil || len(credentials) != 1 || credentials[0].DeviceID != device.ID {
		t.Fatalf("listed credentials %+v, error %v", credentials, err)
	}
	storedDevice, err := store.GetDevice(ctx, device.ID)
	if err != nil || storedDevice.Metadata["sshPort"] != "2222" {
		t.Fatalf("stored device %+v, error %v", storedDevice, err)
	}
}

func TestUpdateActionFinalizesExistingAuditRecord(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "actions.db"), Options{})
	ctx := context.Background()
	startedAt := time.Now().UTC().Add(-time.Second)
	action := Action{
		ID:         "action-a",
		DeviceID:   "device-a",
		ActionType: "wake_on_lan",
		Status:     "running",
		Metadata:   map[string]string{"target": "device-a"},
		StartedAt:  startedAt,
	}
	if _, err := store.AddAction(ctx, action); err != nil {
		t.Fatalf("add running action: %v", err)
	}

	action.Status = "completed"
	action.ResultSummary = "Wake packet sent."
	action.FinishedAt = time.Now().UTC()
	if _, err := store.UpdateAction(ctx, action); err != nil {
		t.Fatalf("finalize action: %v", err)
	}
	actions, err := store.ListActions(ctx)
	if err != nil || len(actions) != 1 {
		t.Fatalf("list actions = %+v, %v", actions, err)
	}
	if actions[0].Status != "completed" || actions[0].FinishedAt.IsZero() || actions[0].ResultSummary != "Wake packet sent." {
		t.Fatalf("final action = %+v", actions[0])
	}

	missing := action
	missing.ID = "missing"
	if _, err := store.UpdateAction(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing action update error = %v, want ErrNotFound", err)
	}
}

func TestActionPaginationAndRetentionAreBounded(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "action-history.db"), Options{})
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)
	for index := 0; index < 6; index++ {
		if _, err := store.AddAction(ctx, Action{
			ID:         fmt.Sprintf("action-%d", index),
			ActionType: "test",
			Status:     "completed",
			StartedAt:  base.Add(time.Duration(index) * time.Minute),
			FinishedAt: base.Add(time.Duration(index) * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}

	page, err := store.ListActionsPage(ctx, 2, 1)
	if err != nil || len(page) != 2 || page[0].ID != "action-4" || page[1].ID != "action-3" {
		t.Fatalf("action page = %+v, %v", page, err)
	}
	if _, err := store.ListActionsPage(ctx, 2, -1); err == nil {
		t.Fatal("expected negative offset to be rejected")
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pruneActions(ctx, tx, 3); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	remaining, err := store.ListActionsPage(ctx, 10, 0)
	if err != nil || len(remaining) != 3 || remaining[0].ID != "action-5" || remaining[2].ID != "action-3" {
		t.Fatalf("retained actions = %+v, %v", remaining, err)
	}
}

func TestDatabasePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	directory := filepath.Join(t.TempDir(), "private")
	dbPath := filepath.Join(directory, "home-mesh.db")
	store := openTestStore(t, dbPath, Options{})
	_ = store

	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if got := directoryInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode %o want 700", got)
	}
	fileInfo, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("database mode %o want 600", got)
	}
}

func openTestStore(t *testing.T, dbPath string, options Options) *Store {
	t.Helper()
	store, err := NewWithOptions(dbPath, options)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func createLegacyDatabase(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatalf("disable legacy foreign keys: %v", err)
	}
	for _, statement := range schemaMigrations[0].statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create legacy schema: %v", err)
		}
	}
	if _, err := db.Exec(`PRAGMA user_version = 0`); err != nil {
		t.Fatalf("set legacy user_version: %v", err)
	}
	return db
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?)`, table).Scan(&exists); err != nil {
		t.Fatalf("check table %q: %v", table, err)
	}
	return exists
}
