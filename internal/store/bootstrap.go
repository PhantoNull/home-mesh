package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

const latestSchemaVersion = 5

type migration struct {
	version    int
	name       string
	statements []string
}

var schemaMigrations = []migration{
	{
		version: 1,
		name:    "initial inventory schema",
		statements: []string{`
			CREATE TABLE IF NOT EXISTS devices (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				hostname TEXT NOT NULL DEFAULT '',
				role TEXT NOT NULL DEFAULT '',
				device_type TEXT NOT NULL DEFAULT '',
				ip_address TEXT NOT NULL DEFAULT '',
				mac_address TEXT NOT NULL DEFAULT '',
				network_segment TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'unknown',
				tags_json TEXT NOT NULL DEFAULT '[]',
				metadata_json TEXT NOT NULL DEFAULT '{}',
				created_at TIMESTAMP NOT NULL,
				updated_at TIMESTAMP NOT NULL
			);

			CREATE TABLE IF NOT EXISTS network_nodes (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				node_type TEXT NOT NULL,
				management_ip TEXT NOT NULL DEFAULT '',
				mac_address TEXT NOT NULL DEFAULT '',
				vendor TEXT NOT NULL DEFAULT '',
				model TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'unknown',
				tags_json TEXT NOT NULL DEFAULT '[]',
				metadata_json TEXT NOT NULL DEFAULT '{}',
				created_at TIMESTAMP NOT NULL,
				updated_at TIMESTAMP NOT NULL
			);

			CREATE TABLE IF NOT EXISTS network_segments (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				segment_type TEXT NOT NULL,
				cidr TEXT NOT NULL DEFAULT '',
				vlan_id INTEGER NOT NULL DEFAULT 0,
				gateway_ip TEXT NOT NULL DEFAULT '',
				dns_domain TEXT NOT NULL DEFAULT '',
				metadata_json TEXT NOT NULL DEFAULT '{}',
				created_at TIMESTAMP NOT NULL,
				updated_at TIMESTAMP NOT NULL
			);

			CREATE TABLE IF NOT EXISTS relations (
				id TEXT PRIMARY KEY,
				source_kind TEXT NOT NULL,
				source_id TEXT NOT NULL,
				target_kind TEXT NOT NULL,
				target_id TEXT NOT NULL,
				relation_type TEXT NOT NULL,
				confidence TEXT NOT NULL DEFAULT 'manual',
				metadata_json TEXT NOT NULL DEFAULT '{}',
				observed_at TIMESTAMP NOT NULL
			);

			CREATE TABLE IF NOT EXISTS actions (
				id TEXT PRIMARY KEY,
				device_id TEXT NOT NULL,
				action_type TEXT NOT NULL,
				status TEXT NOT NULL,
				result_summary TEXT NOT NULL DEFAULT '',
				metadata_json TEXT NOT NULL DEFAULT '{}',
				started_at TIMESTAMP NOT NULL,
				finished_at TIMESTAMP NOT NULL
			);

			CREATE TABLE IF NOT EXISTS ssh_credentials (
				device_id TEXT PRIMARY KEY,
				username TEXT NOT NULL DEFAULT '',
				password_ciphertext TEXT NOT NULL DEFAULT '',
				password_nonce TEXT NOT NULL DEFAULT '',
				key_version INTEGER NOT NULL DEFAULT 1,
				created_at TIMESTAMP NOT NULL,
				updated_at TIMESTAMP NOT NULL,
				FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
			);

			CREATE TABLE IF NOT EXISTS admin_account (
				id INTEGER PRIMARY KEY CHECK (id = 1),
				username TEXT NOT NULL,
				password_hash TEXT NOT NULL,
				created_at TIMESTAMP NOT NULL,
				updated_at TIMESTAMP NOT NULL
			);
		`},
	},
	{
		version: 2,
		name:    "quarantine orphan SSH credentials",
		statements: []string{`
			CREATE TABLE IF NOT EXISTS ssh_credentials_quarantine (
				device_id TEXT PRIMARY KEY,
				username TEXT NOT NULL DEFAULT '',
				password_ciphertext TEXT NOT NULL DEFAULT '',
				password_nonce TEXT NOT NULL DEFAULT '',
				key_version INTEGER NOT NULL DEFAULT 1,
				created_at TIMESTAMP NOT NULL,
				updated_at TIMESTAMP NOT NULL,
				quarantined_at TIMESTAMP NOT NULL,
				quarantine_reason TEXT NOT NULL
			);

			INSERT INTO ssh_credentials_quarantine (
				device_id, username, password_ciphertext, password_nonce, key_version,
				created_at, updated_at, quarantined_at, quarantine_reason
			)
			SELECT credentials.device_id, credentials.username,
				credentials.password_ciphertext, credentials.password_nonce,
				credentials.key_version, credentials.created_at, credentials.updated_at,
				CURRENT_TIMESTAMP, 'missing_device'
			FROM ssh_credentials AS credentials
			LEFT JOIN devices ON devices.id = credentials.device_id
			WHERE devices.id IS NULL
			ON CONFLICT(device_id) DO NOTHING;

			DELETE FROM ssh_credentials
			WHERE NOT EXISTS (
				SELECT 1 FROM devices WHERE devices.id = ssh_credentials.device_id
			);

			CREATE INDEX IF NOT EXISTS idx_relations_source_endpoint
				ON relations(source_kind, source_id);
			CREATE INDEX IF NOT EXISTS idx_relations_target_endpoint
				ON relations(target_kind, target_id);
		`},
	},
	{
		version: 3,
		name:    "redact legacy SSH action payloads",
		statements: []string{`
			UPDATE actions
			SET metadata_json = CASE
					WHEN json_valid(metadata_json) THEN json_remove(metadata_json, '$.command', '$.output')
					ELSE '{}'
				END,
				result_summary = CASE status
					WHEN 'completed' THEN 'SSH command completed.'
					WHEN 'failed' THEN 'SSH command failed.'
					WHEN 'running' THEN 'SSH command is running.'
					ELSE 'SSH command finished.'
				END
			WHERE action_type = 'ssh_command';
		`},
	},
	{
		version: 4,
		name:    "add optimistic concurrency versions",
		statements: []string{
			`ALTER TABLE devices ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1)`,
			`ALTER TABLE network_nodes ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1)`,
			`ALTER TABLE network_segments ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1)`,
			`ALTER TABLE relations ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1)`,
		},
	},
	{
		version: 5,
		name:    "quarantine invalid topology references",
		statements: []string{`
			CREATE TABLE IF NOT EXISTS relations_quarantine (
				id TEXT PRIMARY KEY,
				version INTEGER NOT NULL,
				source_kind TEXT NOT NULL,
				source_id TEXT NOT NULL,
				target_kind TEXT NOT NULL,
				target_id TEXT NOT NULL,
				relation_type TEXT NOT NULL,
				confidence TEXT NOT NULL,
				metadata_json TEXT NOT NULL,
				observed_at TIMESTAMP NOT NULL,
				quarantined_at TIMESTAMP NOT NULL,
				quarantine_reason TEXT NOT NULL
			);

			INSERT INTO relations_quarantine (
				id, version, source_kind, source_id, target_kind, target_id,
				relation_type, confidence, metadata_json, observed_at,
				quarantined_at, quarantine_reason
			)
			SELECT id, version, source_kind, source_id, target_kind, target_id,
				relation_type, confidence, metadata_json, observed_at, CURRENT_TIMESTAMP,
				CASE
					WHEN source_kind NOT IN ('device', 'networkNode', 'networkSegment')
						OR target_kind NOT IN ('device', 'networkNode', 'networkSegment')
						THEN 'unsupported_kind'
					WHEN source_kind = target_kind AND source_id = target_id THEN 'self_relation'
					WHEN (source_kind = 'device' AND NOT EXISTS (SELECT 1 FROM devices WHERE devices.id = relations.source_id))
						OR (source_kind = 'networkNode' AND NOT EXISTS (SELECT 1 FROM network_nodes WHERE network_nodes.id = relations.source_id))
						OR (source_kind = 'networkSegment' AND NOT EXISTS (SELECT 1 FROM network_segments WHERE network_segments.id = relations.source_id))
						THEN 'missing_source'
					ELSE 'missing_target'
				END
			FROM relations
			WHERE source_kind NOT IN ('device', 'networkNode', 'networkSegment')
				OR target_kind NOT IN ('device', 'networkNode', 'networkSegment')
				OR (source_kind = target_kind AND source_id = target_id)
				OR (source_kind = 'device' AND NOT EXISTS (SELECT 1 FROM devices WHERE devices.id = relations.source_id))
				OR (source_kind = 'networkNode' AND NOT EXISTS (SELECT 1 FROM network_nodes WHERE network_nodes.id = relations.source_id))
				OR (source_kind = 'networkSegment' AND NOT EXISTS (SELECT 1 FROM network_segments WHERE network_segments.id = relations.source_id))
				OR (target_kind = 'device' AND NOT EXISTS (SELECT 1 FROM devices WHERE devices.id = relations.target_id))
				OR (target_kind = 'networkNode' AND NOT EXISTS (SELECT 1 FROM network_nodes WHERE network_nodes.id = relations.target_id))
				OR (target_kind = 'networkSegment' AND NOT EXISTS (SELECT 1 FROM network_segments WHERE network_segments.id = relations.target_id))
			ON CONFLICT(id) DO NOTHING;

			DELETE FROM relations
			WHERE id IN (SELECT id FROM relations_quarantine);

			CREATE TABLE IF NOT EXISTS device_segment_quarantine (
				device_id TEXT NOT NULL,
				network_segment TEXT NOT NULL,
				device_version INTEGER NOT NULL,
				quarantined_at TIMESTAMP NOT NULL,
				quarantine_reason TEXT NOT NULL,
				PRIMARY KEY (device_id, network_segment)
			);

			INSERT INTO device_segment_quarantine (
				device_id, network_segment, device_version, quarantined_at, quarantine_reason
			)
			SELECT id, network_segment, version, CURRENT_TIMESTAMP, 'missing_segment'
			FROM devices
			WHERE network_segment <> ''
				AND NOT EXISTS (
					SELECT 1 FROM network_segments
					WHERE network_segments.id = devices.network_segment
				)
			ON CONFLICT(device_id, network_segment) DO NOTHING;

			UPDATE devices
			SET network_segment = '', version = version + 1, updated_at = CURRENT_TIMESTAMP
			WHERE network_segment <> ''
				AND NOT EXISTS (
					SELECT 1 FROM network_segments
					WHERE network_segments.id = devices.network_segment
				);
		`},
	},
}

func (s *Store) migrate(ctx context.Context) error {
	var currentVersion int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&currentVersion); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if currentVersion > latestSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", currentVersion, latestSchemaVersion)
	}

	for _, candidate := range schemaMigrations {
		if candidate.version <= currentVersion {
			continue
		}
		if err := applyMigration(ctx, s.db, candidate); err != nil {
			return err
		}
		currentVersion = candidate.version
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, candidate migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %d (%s): %w", candidate.version, candidate.name, err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, statement := range candidate.statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply migration %d (%s): %w", candidate.version, candidate.name, err)
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", candidate.version)); err != nil {
		return fmt.Errorf("record migration %d (%s): %w", candidate.version, candidate.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %d (%s): %w", candidate.version, candidate.name, err)
	}
	return nil
}

func (s *Store) checkIntegrity(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA integrity_check`)
	if err != nil {
		return fmt.Errorf("run SQLite integrity_check: %w", err)
	}
	defer rows.Close()

	var failures []string
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return fmt.Errorf("read SQLite integrity_check: %w", err)
		}
		if !strings.EqualFold(strings.TrimSpace(result), "ok") {
			failures = append(failures, result)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read SQLite integrity_check: %w", err)
	}
	if len(failures) > 0 {
		return fmt.Errorf("SQLite integrity_check failed: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (s *Store) checkForeignKeys(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("run SQLite foreign_key_check: %w", err)
	}
	defer rows.Close()

	var failures []string
	for rows.Next() {
		var table, parent string
		var rowID sql.NullInt64
		var foreignKeyID int
		if err := rows.Scan(&table, &rowID, &parent, &foreignKeyID); err != nil {
			return fmt.Errorf("read SQLite foreign_key_check: %w", err)
		}
		failures = append(failures, fmt.Sprintf("table=%s rowid=%v parent=%s fk=%d", table, rowID, parent, foreignKeyID))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read SQLite foreign_key_check: %w", err)
	}
	if len(failures) > 0 {
		return fmt.Errorf("SQLite foreign_key_check failed: %s", strings.Join(failures, "; "))
	}
	return nil
}
