package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhantoNull/home-mesh/internal/store"
)

func TestRefreshAllUsesOneConfiguredNmapBatchAndCountsUnknown(t *testing.T) {
	t.Parallel()

	inventory := newMonitorStore(t)
	device, err := inventory.AddDevice(context.Background(), store.Device{
		Name: "server", IPAddress: "192.168.1.10", Metadata: map[string]string{"owner": "home", "sshPort": "2222"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = inventory.AddDevice(context.Background(), store.Device{Name: "IPv6 only", IPAddress: "2001:db8::10"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = inventory.AddNetworkNode(context.Background(), store.NetworkNode{Name: "switch", NodeType: "switch", ManagementIP: "192.168.1.10"})
	if err != nil {
		t.Fatal(err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	refresher := NewRefresherWithOptions(inventory, NewEventBus(), RefresherOptions{NmapPath: executable})
	if !refresher.UsingNmap() {
		t.Fatal("configured executable was not used")
	}
	var calls atomic.Int32
	refresher.nmapScan = func(_ context.Context, path string, ips []string, ports []int) (map[string]nmapScanResult, error) {
		calls.Add(1)
		if path != executable {
			t.Fatalf("nmap path = %q, want %q", path, executable)
		}
		if len(ips) != 1 || ips[0] != "192.168.1.10" {
			t.Fatalf("targets = %v", ips)
		}
		if !slices.Contains(ports, 2222) {
			t.Fatalf("custom SSH port missing from batch: %v", ports)
		}
		return map[string]nmapScanResult{
			"192.168.1.10": {IP: "192.168.1.10", Up: true, OpenPorts: []int{80}},
		}, nil
	}

	result, err := refresher.RefreshAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("nmap calls = %d, want 1", calls.Load())
	}
	if !result.NmapUsed || result.Summary.Checked != 3 || result.Summary.Online != 2 || result.Summary.Unknown != 1 || result.Summary.Offline != 0 {
		t.Fatalf("result = %#v", result)
	}
	if _, exists := device.Metadata["lastReachablePorts"]; exists {
		t.Fatal("input device metadata was mutated")
	}
	persisted, err := inventory.GetDevice(context.Background(), device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Status != "online" || persisted.Metadata["lastReachablePorts"] != "80" {
		t.Fatalf("persisted device = %+v", persisted)
	}
	var refreshedDevice store.Device
	for _, candidate := range result.Devices {
		if candidate.ID == device.ID {
			refreshedDevice = candidate
			break
		}
	}
	if refreshedDevice.Version != persisted.Version || refreshedDevice.Version <= device.Version {
		t.Fatalf("refresh result has stale version: result=%+v persisted=%+v", refreshedDevice, persisted)
	}
}

func TestDeviceOCCRetryPreservesManualFieldsAndReturnsFreshVersion(t *testing.T) {
	inventory := newMonitorStore(t)
	ctx := context.Background()
	original, err := inventory.AddDevice(ctx, store.Device{
		Name: "Server", Role: "server", IPAddress: "192.0.2.10", MACAddress: "00:11:22:33:44:55",
		Metadata: map[string]string{
			"owner": "home", "panelLink": "https://old.home", "panelLinkSource": "auto",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := cloneDevice(original)
	observed.Status = "online"
	observed.IPAddress = "192.0.2.11"
	observed.Hostname = "resolved.home"
	observed.MACAddress = "AA:BB:CC:DD:EE:FF"
	observed.Metadata["lastReachablePorts"] = "22"
	observed.Metadata["panelLink"] = "https://observed.home"
	observed.Metadata["panelLinkSource"] = "auto"

	manual := cloneDevice(original)
	manual.Name = "User managed server"
	manual.Role = "operator"
	manual.MACAddress = "10:20:30:40:50:60"
	manual.Metadata["owner"] = "person"
	// Changing only the source marks the existing link as manual; the pair must be preserved together.
	manual.Metadata["panelLinkSource"] = "manual"
	manual, err = inventory.UpdateDevice(ctx, manual)
	if err != nil {
		t.Fatal(err)
	}

	updated, err := persistIfChanged(ctx, inventory, original, &observed)
	if err != nil || !updated {
		t.Fatalf("persist conflict retry updated=%t error=%v", updated, err)
	}
	if observed.Version != manual.Version+1 || observed.Name != manual.Name || observed.Role != manual.Role {
		t.Fatalf("manual fields or version were lost: observed=%+v manual=%+v", observed, manual)
	}
	if observed.MACAddress != manual.MACAddress || observed.IPAddress != "192.0.2.11" || observed.Hostname != "resolved.home" {
		t.Fatalf("conditional observed fields merged incorrectly: %+v", observed)
	}
	if observed.Status != "online" || observed.Metadata["lastReachablePorts"] != "22" ||
		observed.Metadata["owner"] != "person" || observed.Metadata["panelLink"] != "https://old.home" ||
		observed.Metadata["panelLinkSource"] != "manual" {
		t.Fatalf("observed/manual metadata merge = %+v", observed)
	}
	persisted, err := inventory.GetDevice(ctx, original.ID)
	if err != nil || persisted.Version != observed.Version || persisted.Name != observed.Name || persisted.Status != observed.Status {
		t.Fatalf("persisted device = %+v, %v", persisted, err)
	}
}

func TestDeviceOCCRetryDiscardsObservationWhenTargetChanged(t *testing.T) {
	inventory := newMonitorStore(t)
	ctx := context.Background()
	original, err := inventory.AddDevice(ctx, store.Device{
		Name: "Server", Hostname: "old.home", IPAddress: "192.0.2.10", MACAddress: "00:11:22:33:44:55",
		Metadata: map[string]string{"owner": "home"},
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := cloneDevice(original)
	observed.Status = "online"
	observed.MACAddress = "AA:BB:CC:DD:EE:FF"
	observed.Metadata["lastReachablePorts"] = "22"

	manual := cloneDevice(original)
	manual.IPAddress = "192.0.2.99"
	manual.Hostname = "new.home"
	manual.Metadata["owner"] = "person"
	manual, err = inventory.UpdateDevice(ctx, manual)
	if err != nil {
		t.Fatal(err)
	}

	updated, err := persistIfChanged(ctx, inventory, original, &observed)
	if err != nil || updated {
		t.Fatalf("stale-target observation updated=%t error=%v", updated, err)
	}
	if observed.Version != manual.Version || observed.IPAddress != manual.IPAddress || observed.Hostname != manual.Hostname ||
		observed.Status != manual.Status || observed.MACAddress != manual.MACAddress {
		t.Fatalf("stale target observation was not discarded: observed=%+v manual=%+v", observed, manual)
	}
	if _, exists := observed.Metadata["lastReachablePorts"]; exists {
		t.Fatalf("stale reachability metadata survived: %v", observed.Metadata)
	}
}

func TestNetworkNodeOCCRetryMergesObservationsAndRejectsStaleTarget(t *testing.T) {
	inventory := newMonitorStore(t)
	ctx := context.Background()
	original, err := inventory.AddNetworkNode(ctx, store.NetworkNode{
		Name: "Router", NodeType: "router", ManagementIP: "192.0.2.1", Vendor: "Original",
		MACAddress: "00:11:22:33:44:55", Metadata: map[string]string{"owner": "home"},
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := cloneNetworkNode(original)
	observed.Status = "online"
	observed.MACAddress = "AA:BB:CC:DD:EE:FF"
	observed.Metadata["lastReachablePorts"] = "443"
	manual := cloneNetworkNode(original)
	manual.Vendor = "Manual vendor"
	manual, err = inventory.UpdateNetworkNode(ctx, manual)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := persistNodeIfChanged(ctx, inventory, original, &observed)
	if err != nil || !updated || observed.Version != manual.Version+1 || observed.Vendor != manual.Vendor ||
		observed.MACAddress != "AA:BB:CC:DD:EE:FF" || observed.Metadata["lastReachablePorts"] != "443" {
		t.Fatalf("node retry result=%+v updated=%t error=%v", observed, updated, err)
	}

	newOriginal := observed
	staleObservation := cloneNetworkNode(newOriginal)
	staleObservation.Status = "offline"
	staleObservation.Metadata["lastReachablePorts"] = "80"
	newTarget := cloneNetworkNode(newOriginal)
	newTarget.ManagementIP = "192.0.2.2"
	newTarget, err = inventory.UpdateNetworkNode(ctx, newTarget)
	if err != nil {
		t.Fatal(err)
	}
	updated, err = persistNodeIfChanged(ctx, inventory, newOriginal, &staleObservation)
	if err != nil || updated || staleObservation.Version != newTarget.Version || staleObservation.ManagementIP != newTarget.ManagementIP || staleObservation.Status != newTarget.Status {
		t.Fatalf("node stale target result=%+v updated=%t error=%v", staleObservation, updated, err)
	}
}

func TestBatchConflictOnChangedTargetDiscardsObservation(t *testing.T) {
	inventory := newMonitorStore(t)
	ctx := context.Background()
	original, err := inventory.AddDevice(ctx, store.Device{
		Name: "Server", IPAddress: "192.0.2.10", MACAddress: "00:11:22:33:44:55",
	})
	if err != nil {
		t.Fatal(err)
	}
	refresher := testRefresherWithNmap(t, inventory)
	refresher.nmapScan = func(_ context.Context, _ string, ips []string, _ []int) (map[string]nmapScanResult, error) {
		manual, getErr := inventory.GetDevice(ctx, original.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		manual.IPAddress = "192.0.2.99"
		if _, updateErr := inventory.UpdateDevice(ctx, manual); updateErr != nil {
			t.Fatal(updateErr)
		}
		return map[string]nmapScanResult{
			ips[0]: {Up: true, MAC: "AA:BB:CC:DD:EE:FF", OpenPorts: []int{22}},
		}, nil
	}

	result, err := refresher.RefreshAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Updated != 0 || result.Summary.MACResolved != 0 || result.Summary.Unknown != 1 {
		t.Fatalf("stale scan summary = %+v", result.Summary)
	}
	if len(result.Devices) != 1 {
		t.Fatalf("devices = %+v", result.Devices)
	}
	refreshed := result.Devices[0]
	if refreshed.IPAddress != "192.0.2.99" || refreshed.Version != original.Version+1 ||
		refreshed.Status != "unknown" || refreshed.MACAddress != original.MACAddress {
		t.Fatalf("stale observation survived target change: %+v", refreshed)
	}
	if _, exists := refreshed.Metadata["lastReachablePorts"]; exists {
		t.Fatalf("stale ports survived target change: %+v", refreshed.Metadata)
	}
}

func TestScanAndPublishEmitsPersistedVersion(t *testing.T) {
	inventory := newMonitorStore(t)
	ctx := context.Background()
	original, err := inventory.AddDevice(ctx, store.Device{Name: "Server", IPAddress: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	bus := NewEventBus()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	refresher := NewRefresherWithOptions(inventory, bus, RefresherOptions{NmapPath: executable})
	refresher.nmapScan = func(_ context.Context, _ string, ips []string, _ []int) (map[string]nmapScanResult, error) {
		return map[string]nmapScanResult{ips[0]: {Up: true, OpenPorts: []int{443}}}, nil
	}
	subscriberID, events := bus.Subscribe()
	defer bus.Unsubscribe(subscriberID)

	refresher.scanAndPublish(ctx)
	var emitted store.Device
	for range 3 {
		event := <-events
		if event.Kind == EventDeviceUpdate {
			if err := json.Unmarshal(event.Data, &emitted); err != nil {
				t.Fatal(err)
			}
		}
	}
	persisted, err := inventory.GetDevice(ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if emitted.ID != original.ID || emitted.Version != persisted.Version || emitted.Version <= original.Version {
		t.Fatalf("SSE version is stale: emitted=%+v persisted=%+v", emitted, persisted)
	}
}

func TestFallbackCanonicalizesValidPTRAndDiscardsInvalidPTR(t *testing.T) {
	tests := []struct {
		name     string
		observed string
		want     string
	}{
		{name: "canonical", observed: "Router.Home.ARPA.", want: "router.home.arpa"},
		{name: "invalid", observed: "router_bad.home", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory := newMonitorStore(t)
			original, err := inventory.AddDevice(context.Background(), store.Device{Name: "Router", IPAddress: "192.0.2.1"})
			if err != nil {
				t.Fatal(err)
			}
			refresher := NewRefresherWithOptions(inventory, NewEventBus(), RefresherOptions{
				NmapPath: filepath.Join(t.TempDir(), "missing-nmap"),
			})
			refresher.probes = deterministicProbes()
			refresher.probes.pingHost = func(context.Context, string, time.Duration) (bool, error) {
				return true, nil
			}
			refresher.probes.reverseLookup = func(context.Context, string) (string, error) {
				return test.observed, nil
			}

			result, err := refresher.RefreshAll(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result.Summary.Online != 1 || len(result.Devices) != 1 || result.Devices[0].Hostname != test.want {
				t.Fatalf("refresh result = %+v", result)
			}
			persisted, err := inventory.GetDevice(context.Background(), original.ID)
			if err != nil || persisted.Hostname != test.want {
				t.Fatalf("persisted device = %+v, error=%v", persisted, err)
			}
		})
	}
}

func TestFallbackPreservesTCPEvidenceWhenProbeTimesOut(t *testing.T) {
	inventory := newMonitorStore(t)
	device, err := inventory.AddDevice(context.Background(), store.Device{
		Name: "Server", IPAddress: "192.0.2.10", Metadata: map[string]string{"sshPort": "2222"},
	})
	if err != nil {
		t.Fatal(err)
	}
	node, err := inventory.AddNetworkNode(context.Background(), store.NetworkNode{
		Name: "Switch", NodeType: "switch", ManagementIP: "192.0.2.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	refresher := NewRefresherWithOptions(inventory, NewEventBus(), RefresherOptions{
		NmapPath: filepath.Join(t.TempDir(), "missing-nmap"),
	})
	refresher.probes = deterministicProbes()
	refresher.probes.pingHost = func(_ context.Context, target string, _ time.Duration) (bool, error) {
		return target == device.IPAddress, nil
	}
	refresher.probes.probeTCPPorts = func(_ context.Context, target string, ports []int) (bool, bool, []string, error) {
		switch target {
		case device.IPAddress:
			if !slices.Contains(ports, 2222) {
				t.Fatalf("custom SSH port missing after ping path: %v", ports)
			}
			return true, false, []string{"2222"}, context.DeadlineExceeded
		case node.ManagementIP:
			return false, true, nil, context.DeadlineExceeded
		default:
			t.Fatalf("unexpected target %q", target)
			return false, false, nil, nil
		}
	}

	result, err := refresher.RefreshAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Online != 1 || result.Summary.Degraded != 1 || result.Summary.Unknown != 0 || result.Summary.Updated != 2 {
		t.Fatalf("summary = %+v", result.Summary)
	}
	persistedDevice, err := inventory.GetDevice(context.Background(), device.ID)
	if err != nil || persistedDevice.Status != "online" || persistedDevice.Metadata["lastReachablePorts"] != "2222" {
		t.Fatalf("persisted device = %+v, error=%v", persistedDevice, err)
	}
	persistedNode, err := inventory.GetNetworkNode(context.Background(), node.ID)
	if err != nil || persistedNode.Status != "degraded" {
		t.Fatalf("persisted node = %+v, error=%v", persistedNode, err)
	}
}

func TestBatchRefreshReportsEntityDeletedDuringScanAsPartial(t *testing.T) {
	inventory := newMonitorStore(t)
	ctx := context.Background()
	deleted, err := inventory.AddDevice(ctx, store.Device{Name: "Deleted", IPAddress: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	retained, err := inventory.AddDevice(ctx, store.Device{Name: "Retained", IPAddress: "192.0.2.11"})
	if err != nil {
		t.Fatal(err)
	}
	refresher := testRefresherWithNmap(t, inventory)
	refresher.nmapScan = func(_ context.Context, _ string, _ []string, _ []int) (map[string]nmapScanResult, error) {
		if err := inventory.DeleteDevice(ctx, deleted.ID); err != nil {
			t.Fatal(err)
		}
		return map[string]nmapScanResult{
			deleted.IPAddress:  {Up: true},
			retained.IPAddress: {Up: true},
		}, nil
	}

	result, err := refresher.RefreshAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.Checked != 2 || result.Summary.Skipped != 1 || !result.Summary.Partial ||
		result.Summary.Online != 1 || result.Summary.Updated != 1 {
		t.Fatalf("summary = %+v", result.Summary)
	}
	if len(result.Devices) != 1 || result.Devices[0].ID != retained.ID {
		t.Fatalf("result devices = %+v", result.Devices)
	}
	if _, err := inventory.GetDevice(ctx, deleted.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted device lookup error = %v", err)
	}
	persisted, err := inventory.GetDevice(ctx, retained.ID)
	if err != nil || persisted.Status != "online" {
		t.Fatalf("retained device = %+v, error=%v", persisted, err)
	}
}

func TestParallelRefreshTreatsPerEntityPersistenceErrorsAsPartial(t *testing.T) {
	devices := []store.Device{{ID: "conflict"}, {ID: "updated"}}
	refresher := &Refresher{}
	refreshed, summary, err := refresher.refreshDevicesParallel(context.Background(), devices, func(_ context.Context, device store.Device) (store.Device, bool, string, bool, error) {
		if device.ID == "conflict" {
			return device, false, "unknown", false, fmt.Errorf("persist device: %w", store.ErrConflict)
		}
		device.Status = "online"
		return device, true, device.Status, false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(refreshed) != 2 || summary.Checked != 2 || summary.Skipped != 1 || !summary.Partial ||
		summary.Updated != 1 || summary.Online != 1 || summary.Unknown != 0 {
		t.Fatalf("refreshed=%+v summary=%+v", refreshed, summary)
	}

	nodes := []store.NetworkNode{{ID: "deleted"}, {ID: "updated"}}
	refreshedNodes, nodeSummary, err := refresher.refreshNodesParallel(context.Background(), nodes, func(_ context.Context, node store.NetworkNode) (store.NetworkNode, bool, string, bool, error) {
		if node.ID == "deleted" {
			return node, false, "unknown", false, fmt.Errorf("persist node: %w", store.ErrNotFound)
		}
		node.Status = "degraded"
		return node, true, node.Status, false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(refreshedNodes) != 1 || refreshedNodes[0].ID != "updated" || nodeSummary.Checked != 2 ||
		nodeSummary.Skipped != 1 || !nodeSummary.Partial || nodeSummary.Updated != 1 || nodeSummary.Degraded != 1 {
		t.Fatalf("refreshed nodes=%+v summary=%+v", refreshedNodes, nodeSummary)
	}
}

func TestIncompleteNmapBatchFallsBackInsteadOfMarkingHostsOffline(t *testing.T) {
	inventory := newMonitorStore(t)
	_, err := inventory.AddDevice(context.Background(), store.Device{Name: "Server", IPAddress: "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	refresher := testRefresherWithNmap(t, inventory)
	refresher.nmapScan = func(context.Context, string, []string, []int) (map[string]nmapScanResult, error) {
		return parseNmapXML([]byte(`<nmaprun></nmaprun>`))
	}
	refresher.probes = deterministicProbes()
	refresher.probes.probeTCPPorts = func(context.Context, string, []int) (bool, bool, []string, error) {
		return true, false, []string{"22"}, nil
	}

	result, err := refresher.RefreshAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.NmapUsed || result.Summary.Online != 1 || result.Summary.Offline != 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestRefreshAllFallsBackToProbesAfterOneNmapFailure(t *testing.T) {
	t.Parallel()

	inventory := newMonitorStore(t)
	_, err := inventory.AddDevice(context.Background(), store.Device{Name: "server", IPAddress: "192.168.1.20"})
	if err != nil {
		t.Fatal(err)
	}
	refresher := testRefresherWithNmap(t, inventory)
	var nmapCalls atomic.Int32
	refresher.nmapScan = func(context.Context, string, []string, []int) (map[string]nmapScanResult, error) {
		nmapCalls.Add(1)
		return nil, errors.New("nmap unavailable")
	}
	var tcpCalls atomic.Int32
	refresher.probes = deterministicProbes()
	refresher.probes.probeTCPPorts = func(context.Context, string, []int) (bool, bool, []string, error) {
		tcpCalls.Add(1)
		return true, false, []string{"22"}, nil
	}

	result, err := refresher.RefreshAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if nmapCalls.Load() != 1 || tcpCalls.Load() != 1 {
		t.Fatalf("nmap calls = %d, TCP calls = %d", nmapCalls.Load(), tcpCalls.Load())
	}
	if result.NmapUsed || result.Summary.Online != 1 || result.Summary.Offline != 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestRefreshAllTreatsMissingSuccessfulNmapResultAsOffline(t *testing.T) {
	t.Parallel()

	inventory := newMonitorStore(t)
	_, err := inventory.AddDevice(context.Background(), store.Device{Name: "server", IPAddress: "192.168.1.30"})
	if err != nil {
		t.Fatal(err)
	}
	refresher := testRefresherWithNmap(t, inventory)
	refresher.nmapScan = func(context.Context, string, []string, []int) (map[string]nmapScanResult, error) {
		return map[string]nmapScanResult{}, nil
	}
	refresher.probes = deterministicProbes()
	var fallbackCalls atomic.Int32
	refresher.probes.probeTCPPorts = func(context.Context, string, []int) (bool, bool, []string, error) {
		fallbackCalls.Add(1)
		return false, false, nil, nil
	}

	result, err := refresher.RefreshAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.NmapUsed || result.Summary.Offline != 1 || result.Summary.Unknown != 0 {
		t.Fatalf("result = %#v", result)
	}
	if fallbackCalls.Load() != 0 {
		t.Fatalf("fallback probe calls = %d, want 0", fallbackCalls.Load())
	}
}

func TestRefreshAllWaitsForScanGateWithCallerContext(t *testing.T) {
	t.Parallel()

	inventory := newMonitorStore(t)
	refresher := NewRefresherWithOptions(inventory, NewEventBus(), RefresherOptions{})
	refresher.scanGate <- struct{}{}
	defer func() { <-refresher.scanGate }()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := refresher.RefreshAll(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
}

func TestRefreshWorkerConcurrencyIsBounded(t *testing.T) {
	t.Parallel()

	devices := make([]store.Device, 32)
	var active atomic.Int32
	var peak atomic.Int32
	refresh := func(context.Context, store.Device) (store.Device, bool, string, bool, error) {
		current := active.Add(1)
		for {
			observed := peak.Load()
			if current <= observed || peak.CompareAndSwap(observed, current) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
		return store.Device{Status: "online"}, false, "online", false, nil
	}

	refresher := &Refresher{}
	_, summary, err := refresher.refreshDevicesParallel(context.Background(), devices, refresh)
	if err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got < 2 || got > refreshConcurrency {
		t.Fatalf("peak workers = %d, want 2..%d", got, refreshConcurrency)
	}
	if summary.Online != len(devices) {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestUnavailableConfiguredNmapPathDisablesNmap(t *testing.T) {
	t.Parallel()

	inventory := newMonitorStore(t)
	refresher := NewRefresherWithOptions(inventory, NewEventBus(), RefresherOptions{
		NmapPath: filepath.Join(t.TempDir(), "missing-nmap"),
	})
	if refresher.UsingNmap() {
		t.Fatal("missing configured nmap path was reported as available")
	}
}

func newMonitorStore(t *testing.T) *store.Store {
	t.Helper()
	inventory, err := store.New(filepath.Join(t.TempDir(), "monitor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := inventory.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return inventory
}

func testRefresherWithNmap(t *testing.T, inventory *store.Store) *Refresher {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	refresher := NewRefresherWithOptions(inventory, NewEventBus(), RefresherOptions{NmapPath: executable})
	if !refresher.UsingNmap() {
		t.Fatal("test executable was not resolved")
	}
	return refresher
}

func deterministicProbes() probeSet {
	return probeSet{
		resolveIPv4: func(context.Context, string) (string, error) {
			return "", errors.New("not configured")
		},
		reverseLookup: func(context.Context, string) (string, error) {
			return "", errors.New("not found")
		},
		pingHost: func(context.Context, string, time.Duration) (bool, error) {
			return false, nil
		},
		lookupMAC: func(context.Context, string) (string, error) {
			return "", errors.New("not found")
		},
		probeTCPPorts: func(context.Context, string, []int) (bool, bool, []string, error) {
			return false, false, nil, nil
		},
	}
}
