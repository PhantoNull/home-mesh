package discovery

import (
	"sort"
	"testing"
)

func TestParseNmapPingScan(t *testing.T) {
	t.Parallel()

	output := []byte(`
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-06 20:00 UTC
Nmap scan report for router.local (192.168.1.1)
Host is up (0.0020s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Example Vendor)
Nmap scan report for 192.168.1.25
Host is up (0.0030s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 3.20 seconds
`)

	hosts := parseNmapPingScan(output)
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts", len(hosts))
	}
	if hosts[0].IPAddress != "192.168.1.1" || hosts[0].Hostname != "router.local" {
		t.Fatalf("unexpected first host: %+v", hosts[0])
	}
	if hosts[0].MACAddress != "AA:BB:CC:DD:EE:FF" || hosts[0].Vendor != "Example Vendor" {
		t.Fatalf("unexpected first host metadata: %+v", hosts[0])
	}
	if hosts[1].IPAddress != "192.168.1.25" || hosts[1].Hostname != "" {
		t.Fatalf("unexpected second host: %+v", hosts[1])
	}
}

func TestParseNmapPingScanIgnoresHostsWithoutUpMarker(t *testing.T) {
	t.Parallel()

	output := []byte(`
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-06 20:00 UTC
Nmap scan report for 192.168.1.88
Nmap done: 256 IP addresses (0 hosts up) scanned in 3.20 seconds
`)

	hosts := parseNmapPingScan(output)
	if len(hosts) != 0 {
		t.Fatalf("expected no hosts, got %+v", hosts)
	}
}

func TestCompareIPStringsSortsNumerically(t *testing.T) {
	t.Parallel()

	hosts := []HostMatch{
		{IPAddress: "192.168.1.111"},
		{IPAddress: "192.168.1.11"},
		{IPAddress: "192.168.1.2"},
	}

	sort.Slice(hosts, func(i, j int) bool {
		return compareIPStrings(hosts[i].IPAddress, hosts[j].IPAddress) < 0
	})

	expected := []string{"192.168.1.2", "192.168.1.11", "192.168.1.111"}
	for index, ip := range expected {
		if hosts[index].IPAddress != ip {
			t.Fatalf("unexpected order: %+v", hosts)
		}
	}
}
