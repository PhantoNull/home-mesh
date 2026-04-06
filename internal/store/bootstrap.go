package store

import (
	"context"
	"fmt"
)

func (s *Store) init(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
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
	`); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	return s.seedIfEmpty(ctx)
}

func (s *Store) seedIfEmpty(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices`).Scan(&count); err != nil {
		return fmt.Errorf("count devices: %w", err)
	}
	if count > 0 {
		return nil
	}

	for _, device := range seedDevices() {
		if _, err := s.AddDevice(ctx, device); err != nil {
			return fmt.Errorf("seed device %s: %w", device.ID, err)
		}
	}
	for _, node := range seedNetworkNodes() {
		if _, err := s.AddNetworkNode(ctx, node); err != nil {
			return fmt.Errorf("seed network node %s: %w", node.ID, err)
		}
	}
	for _, segment := range seedNetworkSegments() {
		if _, err := s.AddNetworkSegment(ctx, segment); err != nil {
			return fmt.Errorf("seed network segment %s: %w", segment.ID, err)
		}
	}
	for _, relation := range seedRelations() {
		if _, err := s.AddRelation(ctx, relation); err != nil {
			return fmt.Errorf("seed relation %s: %w", relation.ID, err)
		}
	}
	for _, action := range seedActions() {
		if _, err := s.AddAction(ctx, action); err != nil {
			return fmt.Errorf("seed action %s: %w", action.ID, err)
		}
	}

	return nil
}
