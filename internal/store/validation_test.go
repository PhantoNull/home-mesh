package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

func TestDeviceCanonicalizationAndOptimisticConcurrency(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "devices.db"), Options{})
	ctx := context.Background()

	created, err := inventory.AddDevice(ctx, Device{
		ID:         "  device-a  ",
		Name:       "  Primary server  ",
		Hostname:   "NAS.Home.Arpa.",
		Role:       " STORAGE ",
		DeviceType: " SERVER ",
		IPAddress:  "::ffff:192.0.2.10",
		MACAddress: "aa:bb:cc:dd:ee:ff",
		Status:     " ONLINE ",
		Tags:       []string{" Critical ", "critical", "HOME-SERVER"},
		Metadata: map[string]string{
			" owner ":            " home ",
			"panelLink":          "HTTPS://Router.Home.Arpa:443/admin",
			"panelLinkSource":    " MANUAL ",
			"displayOrder":       " 001 ",
			"lastReachablePorts": "443, 22,443",
			"sshPort":            "ssh",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != 1 || created.ID != "device-a" || created.Name != "Primary server" {
		t.Fatalf("unexpected identity fields: %+v", created)
	}
	if created.Hostname != "nas.home.arpa" || created.Role != "storage" || created.DeviceType != "server" {
		t.Fatalf("unexpected canonical text fields: %+v", created)
	}
	if created.IPAddress != "192.0.2.10" || created.MACAddress != "AA:BB:CC:DD:EE:FF" || created.Status != "online" {
		t.Fatalf("unexpected canonical network fields: %+v", created)
	}
	if fmt.Sprint(created.Tags) != "[critical home-server]" {
		t.Fatalf("tags = %v", created.Tags)
	}
	if created.Metadata["owner"] != "home" || created.Metadata["panelLink"] != "https://router.home.arpa:443/admin" {
		t.Fatalf("metadata = %v", created.Metadata)
	}
	if created.Metadata["panelLinkSource"] != "manual" || created.Metadata["displayOrder"] != "1" ||
		created.Metadata["lastReachablePorts"] != "22,443" || created.Metadata["sshPort"] != "22" {
		t.Fatalf("known metadata = %v", created.Metadata)
	}
	encoded, err := json.Marshal(created)
	if err != nil || !strings.Contains(string(encoded), `"version":1`) {
		t.Fatalf("version missing from JSON %s, %v", encoded, err)
	}

	stale := created
	created.Name = "Updated server"
	updated, err := inventory.UpdateDevice(ctx, created)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != 2 || updated.CreatedAt != created.CreatedAt || updated.Name != "Updated server" {
		t.Fatalf("updated device = %+v", updated)
	}
	stale.Name = "Stale overwrite"
	if _, err := inventory.UpdateDevice(ctx, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update error = %v, want ErrConflict", err)
	}
	stored, err := inventory.GetDevice(ctx, created.ID)
	if err != nil || stored.Version != 2 || stored.Name != "Updated server" {
		t.Fatalf("stored device = %+v, %v", stored, err)
	}
}

func TestNodeSegmentAndRelationCanonicalization(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "topology.db"), Options{})
	ctx := context.Background()

	node, err := inventory.AddNetworkNode(ctx, NetworkNode{
		ID:           "node-a",
		Name:         " Edge router ",
		NodeType:     " ROUTER ",
		ManagementIP: "2001:0db8:0:0::1",
		MACAddress:   "00:11:22:33:44:55",
		Status:       " DEGRADED ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if node.Version != 1 || node.NodeType != "router" || node.ManagementIP != "2001:db8::1" || node.Status != "degraded" {
		t.Fatalf("node = %+v", node)
	}

	segment, err := inventory.AddNetworkSegment(ctx, NetworkSegment{
		ID:          "segment-a",
		Name:        " Office LAN ",
		SegmentType: " VLAN ",
		CIDR:        "192.168.10.42/24",
		VLANID:      4094,
		GatewayIP:   "192.168.10.1",
		DNSDomain:   "OFFICE.Home.Arpa.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if segment.Version != 1 || segment.CIDR != "192.168.10.0/24" || segment.DNSDomain != "office.home.arpa" || segment.SegmentType != "vlan" {
		t.Fatalf("segment = %+v", segment)
	}

	relation, err := inventory.AddRelation(ctx, Relation{
		SourceKind:   "networkNode",
		SourceID:     node.ID,
		TargetKind:   "networkSegment",
		TargetID:     segment.ID,
		RelationType: " MEMBER_OF_SEGMENT ",
		Confidence:   " OBSERVED ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if relation.Version != 1 || relation.RelationType != "member_of_segment" || relation.Confidence != "observed" {
		t.Fatalf("relation = %+v", relation)
	}
	if !strings.HasPrefix(relation.ID, "rel-") {
		t.Fatalf("generated relation ID = %q", relation.ID)
	}
	if _, err := uuid.Parse(strings.TrimPrefix(relation.ID, "rel-")); err != nil {
		t.Fatalf("generated relation ID is not a UUID: %v", err)
	}

	stale := relation
	relation.RelationType = "uplink"
	updated, err := inventory.UpdateRelation(ctx, relation)
	if err != nil || updated.Version != 2 || updated.ObservedAt != relation.ObservedAt {
		t.Fatalf("updated relation = %+v, %v", updated, err)
	}
	if _, err := inventory.UpdateRelation(ctx, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale relation update error = %v", err)
	}
}

func TestConcurrentUpdatesAllowExactlyOneWinner(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "concurrent.db"), Options{})
	ctx := context.Background()
	base, err := inventory.AddDevice(ctx, Device{Name: "Server"})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errorsByWriter := make(chan error, 2)
	var wg sync.WaitGroup
	for _, name := range []string{"Writer one", "Writer two"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			candidate := base
			candidate.Name = name
			<-start
			_, err := inventory.UpdateDevice(ctx, candidate)
			errorsByWriter <- err
		}(name)
	}
	close(start)
	wg.Wait()
	close(errorsByWriter)

	var successes, conflicts int
	for err := range errorsByWriter {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected update error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	stored, err := inventory.GetDevice(ctx, base.ID)
	if err != nil || stored.Version != 2 {
		t.Fatalf("stored device = %+v, %v", stored, err)
	}
}

func TestNodeAndSegmentOptimisticConcurrency(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "node-segment-conflicts.db"), Options{})
	ctx := context.Background()

	node, err := inventory.AddNetworkNode(ctx, NetworkNode{Name: "Router", NodeType: "router"})
	if err != nil {
		t.Fatal(err)
	}
	staleNode := node
	node.Name = "Updated router"
	node, err = inventory.UpdateNetworkNode(ctx, node)
	if err != nil || node.Version != 2 {
		t.Fatalf("updated node = %+v, %v", node, err)
	}
	staleNode.Name = "Stale router"
	if _, err := inventory.UpdateNetworkNode(ctx, staleNode); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale node error = %v", err)
	}

	segment, err := inventory.AddNetworkSegment(ctx, NetworkSegment{Name: "LAN", SegmentType: "lan"})
	if err != nil {
		t.Fatal(err)
	}
	staleSegment := segment
	segment.Name = "Updated LAN"
	segment, err = inventory.UpdateNetworkSegment(ctx, segment)
	if err != nil || segment.Version != 2 {
		t.Fatalf("updated segment = %+v, %v", segment, err)
	}
	staleSegment.Name = "Stale LAN"
	if _, err := inventory.UpdateNetworkSegment(ctx, staleSegment); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale segment error = %v", err)
	}
}

func TestVersionedDeletesRejectStaleCallers(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "versioned-delete.db"), Options{})
	ctx := context.Background()
	device, err := inventory.AddDevice(ctx, Device{Name: "Device"})
	if err != nil {
		t.Fatal(err)
	}
	device.Name = "Updated device"
	device, err = inventory.UpdateDevice(ctx, device)
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.DeleteDeviceVersioned(ctx, device.ID, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale device delete error = %v", err)
	}
	if err := inventory.DeleteDeviceVersioned(ctx, device.ID, device.Version); err != nil {
		t.Fatalf("current device delete error = %v", err)
	}
	if err := inventory.DeleteDeviceVersioned(ctx, device.ID, device.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing device delete error = %v", err)
	}

	node, err := inventory.AddNetworkNode(ctx, NetworkNode{Name: "Node", NodeType: "router"})
	if err != nil {
		t.Fatal(err)
	}
	segment, err := inventory.AddNetworkSegment(ctx, NetworkSegment{Name: "LAN", SegmentType: "lan"})
	if err != nil {
		t.Fatal(err)
	}
	relation, err := inventory.AddRelation(ctx, Relation{
		SourceKind: "networkNode", SourceID: node.ID, TargetKind: "networkSegment", TargetID: segment.ID,
		RelationType: "connected_to",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.DeleteRelationVersioned(ctx, relation.ID, relation.Version+1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale relation delete error = %v", err)
	}
	if err := inventory.DeleteRelationVersioned(ctx, relation.ID, relation.Version); err != nil {
		t.Fatalf("current relation delete error = %v", err)
	}
	if err := inventory.DeleteNetworkNodeVersioned(ctx, node.ID, 0); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid version error = %v", err)
	}
}

func TestCanonicalValidationRejectsInvalidInventory(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "validation.db"), Options{})
	ctx := context.Background()
	device, err := inventory.AddDevice(ctx, Device{ID: "device-a", Name: "Device"})
	if err != nil {
		t.Fatal(err)
	}
	node, err := inventory.AddNetworkNode(ctx, NetworkNode{ID: "node-a", Name: "Node", NodeType: "router"})
	if err != nil {
		t.Fatal(err)
	}

	tags := make([]string, maxTagCount+1)
	for index := range tags {
		tags[index] = fmt.Sprintf("tag-%d", index)
	}
	metadata := make(map[string]string, maxMetadataEntries+1)
	for index := 0; index <= maxMetadataEntries; index++ {
		metadata[fmt.Sprintf("key%d", index)] = "value"
	}

	tests := []struct {
		name string
		run  func() error
	}{
		{"uppercase id", func() error { _, err := inventory.AddDevice(ctx, Device{ID: "Device-A", Name: "Device"}); return err }},
		{"missing name", func() error { _, err := inventory.AddDevice(ctx, Device{}); return err }},
		{"invalid hostname", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", Hostname: "bad_host"})
			return err
		}},
		{"IP option injection", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", IPAddress: "--script=unsafe"})
			return err
		}},
		{"non Ethernet MAC", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", MACAddress: "00:11:22:33:44:55:66:77"})
			return err
		}},
		{"invalid entity status", func() error { _, err := inventory.AddDevice(ctx, Device{Name: "Device", Status: "awake"}); return err }},
		{"non slug role", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", Role: "media server"})
			return err
		}},
		{"missing segment membership", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", NetworkSegment: "missing-segment"})
			return err
		}},
		{"too many tags", func() error { _, err := inventory.AddDevice(ctx, Device{Name: "Device", Tags: tags}); return err }},
		{"too much metadata", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", Metadata: metadata})
			return err
		}},
		{"metadata control character", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", Metadata: map[string]string{"note": "first\nsecond"}})
			return err
		}},
		{"unsafe panel URL", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", Metadata: map[string]string{"panelLink": "javascript:alert(1)"}})
			return err
		}},
		{"panel URL credentials", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", Metadata: map[string]string{"panelLink": "https://admin:secret@router.home"}})
			return err
		}},
		{"invalid display order", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", Metadata: map[string]string{"displayOrder": "-1"}})
			return err
		}},
		{"invalid panel source", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", Metadata: map[string]string{"panelLinkSource": "scan"}})
			return err
		}},
		{"invalid reachable ports", func() error {
			_, err := inventory.AddDevice(ctx, Device{Name: "Device", Metadata: map[string]string{"lastReachablePorts": "22,70000"}})
			return err
		}},
		{"missing node type", func() error { _, err := inventory.AddNetworkNode(ctx, NetworkNode{Name: "Node"}); return err }},
		{"negative VLAN", func() error {
			_, err := inventory.AddNetworkSegment(ctx, NetworkSegment{Name: "LAN", SegmentType: "lan", VLANID: -1})
			return err
		}},
		{"reserved VLAN", func() error {
			_, err := inventory.AddNetworkSegment(ctx, NetworkSegment{Name: "LAN", SegmentType: "lan", VLANID: 4095})
			return err
		}},
		{"unmasked invalid CIDR", func() error {
			_, err := inventory.AddNetworkSegment(ctx, NetworkSegment{Name: "LAN", SegmentType: "lan", CIDR: "192.168.1.500/24"})
			return err
		}},
		{"gateway without CIDR", func() error {
			_, err := inventory.AddNetworkSegment(ctx, NetworkSegment{Name: "LAN", SegmentType: "lan", GatewayIP: "192.168.1.1"})
			return err
		}},
		{"gateway outside CIDR", func() error {
			_, err := inventory.AddNetworkSegment(ctx, NetworkSegment{Name: "LAN", SegmentType: "lan", CIDR: "192.168.1.0/24", GatewayIP: "192.168.2.1"})
			return err
		}},
		{"invalid DNS domain", func() error {
			_, err := inventory.AddNetworkSegment(ctx, NetworkSegment{Name: "LAN", SegmentType: "lan", DNSDomain: "bad_domain"})
			return err
		}},
		{"relation self loop", func() error {
			_, err := inventory.AddRelation(ctx, Relation{SourceKind: "device", SourceID: device.ID, TargetKind: "device", TargetID: device.ID, RelationType: "connected_to"})
			return err
		}},
		{"relation confidence", func() error {
			_, err := inventory.AddRelation(ctx, Relation{SourceKind: "device", SourceID: device.ID, TargetKind: "networkNode", TargetID: node.ID, RelationType: "connected_to", Confidence: "guessed"})
			return err
		}},
		{"relation type", func() error {
			_, err := inventory.AddRelation(ctx, Relation{SourceKind: "device", SourceID: device.ID, TargetKind: "networkNode", TargetID: node.ID, RelationType: "connected to"})
			return err
		}},
		{"credential username", func() error {
			_, err := inventory.UpsertSSHCredential(ctx, SSHCredential{DeviceID: device.ID, PasswordCiphertext: "cipher", PasswordNonce: "nonce"})
			return err
		}},
		{"credential nonce", func() error {
			_, err := inventory.UpsertSSHCredential(ctx, SSHCredential{DeviceID: device.ID, Username: "root", PasswordCiphertext: "cipher"})
			return err
		}},
		{"credential key version", func() error {
			_, err := inventory.UpsertSSHCredential(ctx, SSHCredential{DeviceID: device.ID, Username: "root", PasswordCiphertext: "cipher", PasswordNonce: "nonce", KeyVersion: -1})
			return err
		}},
		{"credential port", func() error {
			_, err := inventory.UpsertSSHCredentialAndPort(ctx, SSHCredential{DeviceID: device.ID, Username: "root", PasswordCiphertext: "cipher", PasswordNonce: "nonce"}, "70000")
			return err
		}},
		{"action status", func() error {
			_, err := inventory.AddAction(ctx, Action{ID: "action-a", ActionType: "test", Status: "pending"})
			return err
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, ErrValidation) {
				t.Fatalf("error = %v, want ErrValidation", err)
			}
		})
	}
	credentials, err := inventory.ListSSHCredentials(ctx)
	if err != nil || len(credentials) != 0 {
		t.Fatalf("invalid credential write was not atomic: %+v, %v", credentials, err)
	}
}

func TestValidationBoundaries(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "boundaries.db"), Options{})
	ctx := context.Background()
	tags := make([]string, maxTagCount)
	for index := range tags {
		tags[index] = fmt.Sprintf("tag-%02d", index)
	}
	accepted, err := inventory.AddDevice(ctx, Device{
		ID:   strings.Repeat("a", maxIDLength),
		Name: strings.Repeat("n", maxNameLength),
		Tags: tags,
		Metadata: map[string]string{
			"boundary": strings.Repeat("v", maxMetadataValueLength),
		},
	})
	if err != nil || len(accepted.Tags) != maxTagCount {
		t.Fatalf("valid boundary payload = %+v, %v", accepted, err)
	}

	tests := []Device{
		{ID: strings.Repeat("a", maxIDLength+1), Name: "Device"},
		{Name: strings.Repeat("n", maxNameLength+1)},
		{Name: "Device", Hostname: strings.Repeat("h", 64) + ".home"},
		{Name: "Device", Metadata: map[string]string{"boundary": strings.Repeat("v", maxMetadataValueLength+1)}},
	}
	for index, device := range tests {
		if _, err := inventory.AddDevice(ctx, device); !errors.Is(err, ErrValidation) {
			t.Fatalf("invalid boundary payload %d error = %v", index, err)
		}
	}
}

func TestSupportedEnumsAreAccepted(t *testing.T) {
	for _, status := range []string{"unknown", "online", "degraded", "offline"} {
		if canonical, err := canonicalEntityStatus(status); err != nil || canonical != status {
			t.Fatalf("entity status %q = %q, %v", status, canonical, err)
		}
	}
	for _, status := range []string{"running", "completed", "failed"} {
		action, err := canonicalizeAction(Action{ID: "action-a", ActionType: "test", Status: status})
		if err != nil || action.Status != status {
			t.Fatalf("action status %q = %+v, %v", status, action, err)
		}
	}
	for _, confidence := range []string{"manual", "observed", "inferred"} {
		relation, err := canonicalizeRelation(Relation{
			ID: "relation-a", SourceKind: "device", SourceID: "device-a",
			TargetKind: "networkNode", TargetID: "node-a", RelationType: "connected_to", Confidence: confidence,
		})
		if err != nil || relation.Confidence != confidence {
			t.Fatalf("relation confidence %q = %+v, %v", confidence, relation, err)
		}
	}
	kinds := []string{"device", "networkNode", "networkSegment"}
	for index, kind := range kinds {
		targetKind := kinds[(index+1)%len(kinds)]
		relation, err := canonicalizeRelation(Relation{
			ID: "relation-a", SourceKind: kind, SourceID: "source-a",
			TargetKind: targetKind, TargetID: "target-a", RelationType: "connected_to", Confidence: "manual",
		})
		if err != nil || relation.SourceKind != kind || relation.TargetKind != targetKind {
			t.Fatalf("relation kind %q -> %q = %+v, %v", kind, targetKind, relation, err)
		}
	}
}

func TestActionAuditFieldsAreImmutableAndTransitionsAreOneWay(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "action-transitions.db"), Options{})
	ctx := context.Background()
	running, err := inventory.AddAction(ctx, Action{
		ID: "action-a", DeviceID: "device-a", ActionType: "wake_on_lan", Status: "running",
	})
	if err != nil {
		t.Fatal(err)
	}

	changedDevice := running
	changedDevice.DeviceID = "device-b"
	changedDevice.Status = "completed"
	changedDevice.FinishedAt = running.StartedAt.Add(time.Second)
	if _, err := inventory.UpdateAction(ctx, changedDevice); !errors.Is(err, ErrValidation) {
		t.Fatalf("mutable action identity error = %v", err)
	}
	stillRunning := running
	stillRunning.Status = "running"
	if _, err := inventory.UpdateAction(ctx, stillRunning); !errors.Is(err, ErrConflict) {
		t.Fatalf("running-to-running transition error = %v", err)
	}

	finished := running
	finished.Status = "completed"
	finished.ResultSummary = "Wake packet sent."
	finished.FinishedAt = running.StartedAt.Add(time.Second)
	finished, err = inventory.UpdateAction(ctx, finished)
	if err != nil || finished.Status != "completed" {
		t.Fatalf("finished action = %+v, %v", finished, err)
	}
	finished.Status = "failed"
	if _, err := inventory.UpdateAction(ctx, finished); !errors.Is(err, ErrConflict) {
		t.Fatalf("second terminal transition error = %v", err)
	}

	if _, err := inventory.AddAction(ctx, Action{
		ID: "action-b", ActionType: "test", Status: "completed",
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("terminal action without finish time error = %v", err)
	}
	if _, err := inventory.AddAction(ctx, Action{
		ID: "action-c", ActionType: "test", Status: "running", FinishedAt: fixedTestTime(),
	}); !errors.Is(err, ErrValidation) {
		t.Fatalf("running action with finish time error = %v", err)
	}

	concurrent, err := inventory.AddAction(ctx, Action{ID: "action-d", ActionType: "test", Status: "running"})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, status := range []string{"completed", "failed"} {
		wg.Add(1)
		go func(status string) {
			defer wg.Done()
			candidate := concurrent
			candidate.Status = status
			candidate.FinishedAt = concurrent.StartedAt.Add(time.Second)
			<-start
			_, err := inventory.UpdateAction(ctx, candidate)
			results <- err
		}(status)
	}
	close(start)
	wg.Wait()
	close(results)
	var successes, conflicts int
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent action finalization error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("action finalizations successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestCredentialAndPortCanonicalizationBumpsDeviceVersion(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "credential-version.db"), Options{})
	ctx := context.Background()
	device, err := inventory.AddDevice(ctx, Device{ID: "device-a", Name: "Device", Metadata: map[string]string{"owner": "home"}})
	if err != nil {
		t.Fatal(err)
	}

	credential, err := inventory.UpsertSSHCredentialAndPort(ctx, SSHCredential{
		DeviceID:           " device-a ",
		Username:           " root ",
		PasswordCiphertext: " cipher ",
		PasswordNonce:      " nonce ",
	}, "ssh")
	if err != nil {
		t.Fatal(err)
	}
	if credential.Username != "root" || credential.PasswordCiphertext != "cipher" || credential.KeyVersion != 1 {
		t.Fatalf("credential = %+v", credential)
	}
	storedDevice, err := inventory.GetDevice(ctx, device.ID)
	if err != nil || storedDevice.Version != 2 || storedDevice.Metadata["owner"] != "home" || storedDevice.Metadata["sshPort"] != "22" {
		t.Fatalf("stored device = %+v, %v", storedDevice, err)
	}
	device.Name = "Stale write"
	if _, err := inventory.UpdateDevice(ctx, device); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update after credential metadata patch = %v", err)
	}
	if _, err := inventory.UpsertSSHCredential(ctx, SSHCredential{DeviceID: "missing-device", Username: "root", PasswordCiphertext: "cipher", PasswordNonce: "nonce"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing credential device error = %v", err)
	}
}

func TestLegacyMixedCaseIDsRemainUsableWithoutRewriting(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-id.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, candidate := range schemaMigrations[:3] {
		if err := applyMigration(ctx, db, candidate); err != nil {
			t.Fatal(err)
		}
	}
	now := fixedTestTime()
	if _, err := db.Exec(`INSERT INTO devices (id, name, created_at, updated_at) VALUES ('LegacyDevice', 'Legacy', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	inventory := openTestStore(t, dbPath, Options{})
	device, err := inventory.GetDevice(ctx, "LegacyDevice")
	if err != nil || device.Version != 1 {
		t.Fatalf("legacy device = %+v, %v", device, err)
	}
	device.Name = "Updated legacy"
	device, err = inventory.UpdateDevice(ctx, device)
	if err != nil || device.ID != "LegacyDevice" || device.Version != 2 {
		t.Fatalf("updated legacy device = %+v, %v", device, err)
	}
	credential, err := inventory.UpsertSSHCredential(ctx, SSHCredential{
		DeviceID: "LegacyDevice", Username: "root", PasswordCiphertext: "cipher", PasswordNonce: "nonce",
	})
	if err != nil || credential.DeviceID != "LegacyDevice" {
		t.Fatalf("legacy credential = %+v, %v", credential, err)
	}
	if _, err := inventory.AddDevice(ctx, Device{ID: "NewUppercaseID", Name: "New"}); !errors.Is(err, ErrValidation) {
		t.Fatalf("new mixed-case ID error = %v", err)
	}
}

func TestDeletingSegmentClearsMembershipAndBumpsDeviceVersion(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "segment-membership.db"), Options{})
	ctx := context.Background()
	segment, err := inventory.AddNetworkSegment(ctx, NetworkSegment{Name: "LAN", SegmentType: "lan"})
	if err != nil {
		t.Fatal(err)
	}
	device, err := inventory.AddDevice(ctx, Device{Name: "Device", NetworkSegment: segment.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.DeleteNetworkSegment(ctx, segment.ID); err != nil {
		t.Fatal(err)
	}
	stored, err := inventory.GetDevice(ctx, device.ID)
	if err != nil || stored.NetworkSegment != "" || stored.Version != device.Version+1 {
		t.Fatalf("device after segment deletion = %+v, %v", stored, err)
	}
}

func TestVersionMigrationIsAtomicAndPreservesLegacyRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-versions.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	now := fixedTestTime()
	for _, candidate := range schemaMigrations[:3] {
		if err := applyMigration(context.Background(), db, candidate); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO devices (id, name, created_at, updated_at) VALUES ('device-a', 'Device', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO network_nodes (id, name, node_type, created_at, updated_at) VALUES ('node-a', 'Node', 'router', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO network_segments (id, name, segment_type, created_at, updated_at) VALUES ('segment-a', 'Segment', 'lan', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO relations (id, source_kind, source_id, target_kind, target_id, relation_type, observed_at) VALUES ('relation-a', 'device', 'device-a', 'networkNode', 'node-a', 'connected_to', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	inventory := openTestStore(t, dbPath, Options{})
	ctx := context.Background()
	device, err := inventory.GetDevice(ctx, "device-a")
	if err != nil || device.Version != 1 {
		t.Fatalf("migrated device = %+v, %v", device, err)
	}
	node, err := inventory.GetNetworkNode(ctx, "node-a")
	if err != nil || node.Version != 1 {
		t.Fatalf("migrated node = %+v, %v", node, err)
	}
	segment, err := inventory.GetNetworkSegment(ctx, "segment-a")
	if err != nil || segment.Version != 1 {
		t.Fatalf("migrated segment = %+v, %v", segment, err)
	}
	relation, err := inventory.GetRelation(ctx, "relation-a")
	if err != nil || relation.Version != 1 {
		t.Fatalf("migrated relation = %+v, %v", relation, err)
	}
	if _, err := inventory.db.Exec(`UPDATE devices SET version = 0 WHERE id = 'device-a'`); err == nil {
		t.Fatal("version CHECK accepted zero")
	}
}

func TestVersionMigrationRollsBackPartialAlterations(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "version-rollback.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for _, candidate := range schemaMigrations[:3] {
		if err := applyMigration(ctx, db, candidate); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`ALTER TABLE network_nodes ADD COLUMN version INTEGER NOT NULL DEFAULT 1`); err != nil {
		t.Fatal(err)
	}
	if err := applyMigration(ctx, db, schemaMigrations[3]); err == nil {
		t.Fatal("expected duplicate version column to fail migration")
	}
	if databaseColumnExists(t, db, "devices", "version") {
		t.Fatal("failed migration left devices.version behind")
	}
	if !databaseColumnExists(t, db, "network_nodes", "version") {
		t.Fatal("failed migration removed the pre-existing network_nodes.version")
	}
	var schemaVersion int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&schemaVersion); err != nil || schemaVersion != 3 {
		t.Fatalf("schema version = %d, %v", schemaVersion, err)
	}
}

func TestDemoSeedProducesCanonicalVersionedEntities(t *testing.T) {
	inventory := openTestStore(t, filepath.Join(t.TempDir(), "canonical-seed.db"), Options{SeedDemo: true})
	snapshot, err := inventory.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range snapshot.Devices {
		canonical, err := canonicalizeExistingDevice(device)
		if err != nil || device.Version != 1 || !reflect.DeepEqual(device, canonical) {
			t.Fatalf("non-canonical seeded device = %+v, canonical=%+v, %v", device, canonical, err)
		}
	}
	for _, node := range snapshot.NetworkNodes {
		canonical, err := canonicalizeExistingNetworkNode(node)
		if err != nil || node.Version != 1 || !reflect.DeepEqual(node, canonical) {
			t.Fatalf("non-canonical seeded node = %+v, canonical=%+v, %v", node, canonical, err)
		}
	}
	for _, segment := range snapshot.NetworkSegments {
		canonical, err := canonicalizeExistingNetworkSegment(segment)
		if err != nil || segment.Version != 1 || !reflect.DeepEqual(segment, canonical) {
			t.Fatalf("non-canonical seeded segment = %+v, canonical=%+v, %v", segment, canonical, err)
		}
	}
	for _, relation := range snapshot.Relations {
		canonical, err := canonicalizeExistingRelation(relation)
		if err != nil || relation.Version != 1 || !reflect.DeepEqual(relation, canonical) {
			t.Fatalf("non-canonical seeded relation = %+v, canonical=%+v, %v", relation, canonical, err)
		}
	}
}

func databaseColumnExists(t *testing.T, db *sql.DB, table string, column string) bool {
	t.Helper()
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%q)`, table))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if name == column {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return false
}

func fixedTestTime() time.Time {
	return time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
}
