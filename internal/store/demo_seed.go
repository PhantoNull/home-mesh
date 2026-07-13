package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (s *Store) seedDemoIfEmpty(ctx context.Context, seed func(context.Context, *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin demo seed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var rows int
	if err := tx.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM devices) +
			(SELECT COUNT(*) FROM network_nodes) +
			(SELECT COUNT(*) FROM network_segments) +
			(SELECT COUNT(*) FROM relations) +
			(SELECT COUNT(*) FROM actions) +
			(SELECT COUNT(*) FROM ssh_credentials) +
			(SELECT COUNT(*) FROM ssh_credentials_quarantine) +
			(SELECT COUNT(*) FROM admin_account)
	`).Scan(&rows); err != nil {
		return fmt.Errorf("check database before demo seed: %w", err)
	}
	if rows > 0 {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("finish skipped demo seed: %w", err)
		}
		return nil
	}

	if err := seed(ctx, tx); err != nil {
		return fmt.Errorf("seed demo data: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit demo seed: %w", err)
	}
	return nil
}

func seedDemoData(ctx context.Context, tx *sql.Tx) error {
	now := time.Now().UTC()
	for _, device := range seedDevices() {
		tagsJSON, metadataJSON, err := marshalJSONFields(device.Tags, device.Metadata)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO devices (
				id, name, hostname, role, device_type, ip_address, mac_address,
				network_segment, status, tags_json, metadata_json, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, device.ID, device.Name, device.Hostname, device.Role, device.DeviceType,
			device.IPAddress, device.MACAddress, device.NetworkSegment, device.Status,
			tagsJSON, metadataJSON, now, now); err != nil {
			return fmt.Errorf("insert demo device %s: %w", device.ID, err)
		}
	}

	for _, node := range seedNetworkNodes() {
		tagsJSON, metadataJSON, err := marshalJSONFields(node.Tags, node.Metadata)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO network_nodes (
				id, name, node_type, management_ip, mac_address, vendor, model,
				status, tags_json, metadata_json, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, node.ID, node.Name, node.NodeType, node.ManagementIP, node.MACAddress,
			node.Vendor, node.Model, node.Status, tagsJSON, metadataJSON, now, now); err != nil {
			return fmt.Errorf("insert demo network node %s: %w", node.ID, err)
		}
	}

	for _, segment := range seedNetworkSegments() {
		_, metadataJSON, err := marshalJSONFields(nil, segment.Metadata)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO network_segments (
				id, name, segment_type, cidr, vlan_id, gateway_ip, dns_domain,
				metadata_json, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, segment.ID, segment.Name, segment.SegmentType, segment.CIDR, segment.VLANID,
			segment.GatewayIP, segment.DNSDomain, metadataJSON, now, now); err != nil {
			return fmt.Errorf("insert demo network segment %s: %w", segment.ID, err)
		}
	}

	for _, relation := range seedRelations() {
		_, metadataJSON, err := marshalJSONFields(nil, relation.Metadata)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO relations (
				id, source_kind, source_id, target_kind, target_id, relation_type,
				confidence, metadata_json, observed_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, relation.ID, relation.SourceKind, relation.SourceID, relation.TargetKind,
			relation.TargetID, relation.RelationType, relation.Confidence, metadataJSON, now); err != nil {
			return fmt.Errorf("insert demo relation %s: %w", relation.ID, err)
		}
	}

	for _, action := range seedActions() {
		_, metadataJSON, err := marshalJSONFields(nil, action.Metadata)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO actions (
				id, device_id, action_type, status, result_summary, metadata_json,
				started_at, finished_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, action.ID, action.DeviceID, action.ActionType, action.Status,
			action.ResultSummary, metadataJSON, action.StartedAt, action.FinishedAt); err != nil {
			return fmt.Errorf("insert demo action %s: %w", action.ID, err)
		}
	}

	return nil
}
