package monitor

import (
	"context"
	"slices"
	"strconv"
	"testing"

	"github.com/PhantoNull/home-mesh/internal/store"
)

func TestCanonicalDeviceTargetPrefersExplicitIPv4(t *testing.T) {
	resolveCalls := 0
	refresher := &Refresher{probes: probeSet{
		resolveIPv4: func(context.Context, string) (string, error) {
			resolveCalls++
			return "192.0.2.99", nil
		},
	}}
	device := store.Device{IPAddress: "::ffff:192.0.2.10", Hostname: "other.example"}

	target, ok, err := refresher.canonicalDeviceTarget(context.Background(), &device)
	if err != nil || !ok || target != "192.0.2.10" {
		t.Fatalf("target = %q, ok=%t, error=%v", target, ok, err)
	}
	if resolveCalls != 0 {
		t.Fatalf("hostname resolver called %d times", resolveCalls)
	}
	if device.IPAddress != "192.0.2.10" {
		t.Fatalf("canonical configured IP = %q", device.IPAddress)
	}
}

func TestCanonicalDeviceTargetKeepsResolvedIPEphemeral(t *testing.T) {
	refresher := &Refresher{probes: probeSet{
		resolveIPv4: func(_ context.Context, hostname string) (string, error) {
			if hostname != "host.example" {
				t.Fatalf("resolved hostname = %q", hostname)
			}
			return "192.0.2.20", nil
		},
	}}
	device := store.Device{Hostname: "host.example"}

	target, ok, err := refresher.canonicalDeviceTarget(context.Background(), &device)
	if err != nil || !ok || target != "192.0.2.20" {
		t.Fatalf("target = %q, ok=%t, error=%v", target, ok, err)
	}
	if device.IPAddress != "" {
		t.Fatalf("DNS result leaked into configured IP: %q", device.IPAddress)
	}
}

func TestCanonicalDeviceTargetDoesNotResolveWhenExplicitIPIsUnsupported(t *testing.T) {
	resolveCalls := 0
	refresher := &Refresher{probes: probeSet{
		resolveIPv4: func(context.Context, string) (string, error) {
			resolveCalls++
			return "192.0.2.20", nil
		},
	}}
	device := store.Device{IPAddress: "2001:db8::10", Hostname: "host.example"}

	if target, ok, err := refresher.canonicalDeviceTarget(context.Background(), &device); err != nil || ok || target != "" {
		t.Fatalf("target = %q, ok=%t, error=%v", target, ok, err)
	}
	if resolveCalls != 0 {
		t.Fatalf("hostname resolver called %d times", resolveCalls)
	}
}

func TestApplyNmapToDeviceDoesNotMutateInputMetadata(t *testing.T) {
	t.Parallel()

	original := store.Device{
		Metadata: map[string]string{"owner": "home"},
	}
	updated := applyNmapToDevice(original, nmapScanResult{Up: true, OpenPorts: []int{22}})

	if _, exists := original.Metadata["lastReachablePorts"]; exists {
		t.Fatal("input metadata was mutated")
	}
	if got := updated.Metadata["lastReachablePorts"]; got != "22" {
		t.Fatalf("lastReachablePorts = %q, want 22", got)
	}
}

func TestCandidatePortsIncludesConfiguredSSHPortAndBoundsBatchUnion(t *testing.T) {
	device := store.Device{Metadata: map[string]string{"sshPort": "2222"}}
	if ports := candidatePorts(device); !slices.Contains(ports, 2222) {
		t.Fatalf("candidate ports = %v", ports)
	}

	devices := make([]store.Device, 100)
	for index := range devices {
		devices[index].Metadata = map[string]string{"sshPort": strconv.Itoa(10000 + index)}
	}
	ports := batchCandidatePorts(devices, nil)
	if len(ports) != maxBatchScanPorts {
		t.Fatalf("batch candidate count = %d, want %d", len(ports), maxBatchScanPorts)
	}
	for _, required := range allCandidatePorts() {
		if !slices.Contains(ports, required) {
			t.Fatalf("base port %d missing from %v", required, ports)
		}
	}
	if !slices.Contains(ports, 10000) || slices.Contains(ports, 10099) {
		t.Fatalf("bounded custom port union = %v", ports)
	}
}

func TestDerivePanelLinkPrefersHTTPS(t *testing.T) {
	t.Parallel()

	link, source, ok := derivePanelLink(map[string]string{}, "router.local", []string{"80", "443"})
	if !ok {
		t.Fatal("expected panel link")
	}
	if link != "https://router.local" {
		t.Fatalf("got %q", link)
	}
	if source != "auto" {
		t.Fatalf("got source %q", source)
	}
}

func TestDerivePanelLinkKeepsManualValue(t *testing.T) {
	t.Parallel()

	link, source, ok := derivePanelLink(map[string]string{
		"panelLink":       "https://custom.local",
		"panelLinkSource": "manual",
	}, "router.local", []string{"443"})
	if ok || link != "" || source != "" {
		t.Fatalf("manual link should not be overwritten, got ok=%v link=%q source=%q", ok, link, source)
	}
}

func TestDerivePanelLinkClearsStaleAutoValue(t *testing.T) {
	t.Parallel()

	link, source, ok := derivePanelLink(map[string]string{
		"panelLink":       "https://old.local",
		"panelLinkSource": "auto",
	}, "router.local", nil)
	if !ok {
		t.Fatal("expected stale auto value to be cleared")
	}
	if link != "" || source != "" {
		t.Fatalf("expected clear signal, got link=%q source=%q", link, source)
	}
}
