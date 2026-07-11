package monitor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhantoNull/home-mesh/internal/store"
)

func TestRefreshAllUsesOneConfiguredNmapBatchAndCountsUnknown(t *testing.T) {
	t.Parallel()

	inventory := newMonitorStore(t)
	device, err := inventory.AddDevice(context.Background(), store.Device{
		Name: "server", IPAddress: "192.168.1.10", Metadata: map[string]string{"owner": "home"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = inventory.AddDevice(context.Background(), store.Device{Name: "invalid", IPAddress: "--script=unsafe"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = inventory.AddNetworkNode(context.Background(), store.NetworkNode{Name: "switch", ManagementIP: "192.168.1.10"})
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
	refresher.nmapScan = func(_ context.Context, path string, ips []string, _ []int) (map[string]nmapScanResult, error) {
		calls.Add(1)
		if path != executable {
			t.Fatalf("nmap path = %q, want %q", path, executable)
		}
		if len(ips) != 1 || ips[0] != "192.168.1.10" {
			t.Fatalf("targets = %v", ips)
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
