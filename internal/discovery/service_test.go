package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

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

func TestScanNmapXMLStreamEmitsCompletedHostsBeforeDocumentEnds(t *testing.T) {
	reader, writer := io.Pipe()
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})

	hosts := make(chan HostMatch, 4)
	done := make(chan error, 1)
	go func() {
		done <- scanNmapXMLStream(reader, func(host HostMatch) error {
			hosts <- host
			return nil
		})
	}()

	_, err := io.WriteString(writer, `<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="Acme"/><hostnames><hostname name="fallback" type="user"/><hostname name="router.local." type="PTR"/></hostnames></host>`)
	if err != nil {
		t.Fatalf("write first XML host: %v", err)
	}

	select {
	case host := <-hosts:
		if host.IPAddress != "192.168.1.10" || host.Hostname != "router.local" || host.MACAddress != "AA:BB:CC:DD:EE:FF" || host.Vendor != "Acme" {
			t.Fatalf("unexpected streamed host: %+v", host)
		}
	case err := <-done:
		t.Fatalf("parser ended before document completion: %v", err)
	case <-time.After(time.Second):
		t.Fatal("completed XML host was not emitted incrementally")
	}

	_, err = io.WriteString(writer, `<host><status state="down"/><address addr="192.168.1.20" addrtype="ipv4"/></host><host><status state="up"/><address addr="2001:db8::1" addrtype="ipv6"/></host><host><status state="up"/><address addr="192.168.1.30" addrtype="ipv4"/></host></nmaprun>`)
	if err != nil {
		t.Fatalf("write remaining XML: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close XML writer: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("scanNmapXMLStream returned error: %v", err)
	}

	select {
	case host := <-hosts:
		if host.IPAddress != "192.168.1.30" {
			t.Fatalf("unexpected second streamed host: %+v", host)
		}
	default:
		t.Fatal("second up IPv4 host was not emitted")
	}
	select {
	case host := <-hosts:
		t.Fatalf("unexpected extra streamed host: %+v", host)
	default:
	}
}

func TestSuggestedIPv4CIDRBoundsWideNetworksToContaining24(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		mask net.IPMask
		want string
		ok   bool
	}{
		{name: "wide private", ip: "10.23.45.67", mask: net.CIDRMask(8, 32), want: "10.23.45.0/24", ok: true},
		{name: "existing 24", ip: "192.168.7.42", mask: net.CIDRMask(24, 32), want: "192.168.7.0/24", ok: true},
		{name: "narrow private", ip: "172.16.8.19", mask: net.CIDRMask(28, 32), want: "172.16.8.16/28", ok: true},
		{name: "link local", ip: "169.254.4.9", mask: net.CIDRMask(16, 32), want: "169.254.4.0/24", ok: true},
		{name: "public", ip: "203.0.113.9", mask: net.CIDRMask(24, 32), ok: false},
		{name: "cgnat", ip: "100.64.0.9", mask: net.CIDRMask(24, 32), ok: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := suggestedIPv4CIDR(net.ParseIP(test.ip), test.mask)
			if got != test.want || ok != test.ok {
				t.Fatalf("suggestedIPv4CIDR() = (%q, %t), want (%q, %t)", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestScanCIDRStreamsAndDeduplicatesPointToPointRangeWithOneProcess(t *testing.T) {
	commandCalls := 0
	var commandArgs []string
	service := newNmapHelperService(t, "hosts", func(args []string) {
		commandCalls++
		commandArgs = append([]string(nil), args...)
	})

	var streamed []string
	result, err := service.ScanCIDRStream(context.Background(), "192.0.2.10/31", func(host HostMatch) error {
		streamed = append(streamed, host.IPAddress)
		return nil
	})
	if err != nil {
		t.Fatalf("ScanCIDRStream returned error: %v", err)
	}

	if commandCalls != 1 {
		t.Fatalf("started %d nmap processes, want 1", commandCalls)
	}
	if got := commandArgs[len(commandArgs)-1]; got != "192.0.2.10/31" {
		t.Fatalf("nmap target = %q, want %q", got, "192.0.2.10/31")
	}
	joinedArgs := " " + strings.Join(commandArgs, " ") + " "
	if !strings.Contains(joinedArgs, " -oX - ") {
		t.Fatalf("nmap args %v do not request XML on stdout", commandArgs)
	}
	if strings.Contains(joinedArgs, " --disable-arp-ping ") {
		t.Fatalf("nmap args %v disable ARP discovery", commandArgs)
	}
	assertIPs(t, streamed, []string{"192.0.2.11", "192.0.2.10"})

	resultIPs := make([]string, len(result.Hosts))
	for index, host := range result.Hosts {
		resultIPs[index] = host.IPAddress
	}
	assertIPs(t, resultIPs, []string{"192.0.2.10", "192.0.2.11"})
	if result.Hosts[0].Hostname != "host-10.example" {
		t.Fatalf("hostname = %q, want %q", result.Hosts[0].Hostname, "host-10.example")
	}
	if result.Hosts[0].MACAddress != "AA:BB:CC:DD:EE:10" || result.Hosts[0].Vendor != "Example Vendor" {
		t.Fatalf("unexpected link-layer metadata: %+v", result.Hosts[0])
	}
}

func TestScanCIDRPassesSingleHostRangesWithoutAddressExpansion(t *testing.T) {
	tests := []string{
		"192.0.2.10/32",
		"255.255.255.255/32",
	}

	for _, cidr := range tests {
		t.Run(cidr, func(t *testing.T) {
			commandCalls := 0
			var commandArgs []string
			service := newNmapHelperService(t, "hosts", func(args []string) {
				commandCalls++
				commandArgs = append([]string(nil), args...)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if _, err := service.ScanCIDR(ctx, cidr); err != nil {
				t.Fatalf("ScanCIDR returned error: %v", err)
			}
			if commandCalls != 1 {
				t.Fatalf("started %d nmap processes, want 1", commandCalls)
			}
			if got := commandArgs[len(commandArgs)-1]; got != cidr {
				t.Fatalf("nmap target = %q, want %q", got, cidr)
			}
		})
	}
}

func TestServiceRejectsConcurrentScanAndReleasesSlotAfterCancellation(t *testing.T) {
	commandStarted := make(chan struct{})
	service := newNmapHelperService(t, "block", func([]string) {
		close(commandStarted)
	})
	firstContext, cancelFirst := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() {
		_, err := service.ScanCIDR(firstContext, "192.0.2.0/24")
		firstResult <- err
	}()

	select {
	case <-commandStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("first scan did not start")
	}

	if _, err := service.ScanCIDR(context.Background(), "198.51.100.0/24"); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("concurrent scan error = %v, want %v", err, ErrScanInProgress)
	}

	cancelFirst()
	select {
	case err := <-firstResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled scan error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled scan did not stop")
	}

	service.commandContext = newNmapHelperService(t, "hosts", nil).commandContext
	if _, err := service.ScanCIDR(context.Background(), "203.0.113.0/24"); err != nil {
		t.Fatalf("scan after cancellation returned error: %v", err)
	}
}

func TestScanCIDRReturnsEveryNmapExitError(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		wantDetail string
	}{
		{name: "silent exit one", mode: "exit-silent"},
		{name: "stderr is preserved", mode: "exit-stderr", wantDetail: "simulated nmap failure"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newNmapHelperService(t, test.mode, nil)
			_, err := service.ScanCIDR(context.Background(), "192.0.2.0/24")
			if err == nil {
				t.Fatal("ScanCIDR returned nil error")
			}
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) {
				t.Fatalf("ScanCIDR error = %v, want wrapped exec.ExitError", err)
			}
			if test.wantDetail != "" && !strings.Contains(err.Error(), test.wantDetail) {
				t.Fatalf("ScanCIDR error = %q, want detail %q", err, test.wantDetail)
			}
		})
	}
}

func TestScanCIDRRejectsUnsupportedNetworksBeforeStartingNmap(t *testing.T) {
	tests := []string{
		"2001:db8::/64",
		"192.0.0.0/15",
	}

	for _, cidr := range tests {
		t.Run(cidr, func(t *testing.T) {
			commandCalls := 0
			service := newNmapHelperService(t, "hosts", func([]string) {
				commandCalls++
			})

			if _, err := service.ScanCIDR(context.Background(), cidr); err == nil {
				t.Fatal("ScanCIDR returned nil error")
			}
			if commandCalls != 0 {
				t.Fatalf("started %d nmap processes, want 0", commandCalls)
			}
		})
	}
}

func TestScanCIDRRejectsNonLocalNetworksByDefault(t *testing.T) {
	tests := []string{
		"203.0.113.0/24",
		"100.64.0.0/24",
		"127.0.0.0/24",
	}

	for _, cidr := range tests {
		t.Run(cidr, func(t *testing.T) {
			commandCalls := 0
			service := newNmapHelperServiceWithOptions(t, "hosts", Options{}, func([]string) {
				commandCalls++
			})

			if _, err := service.ScanCIDR(context.Background(), cidr); !errors.Is(err, ErrNetworkNotAllowed) {
				t.Fatalf("ScanCIDR error = %v, want %v", err, ErrNetworkNotAllowed)
			}
			if commandCalls != 0 {
				t.Fatalf("started %d nmap processes, want 0", commandCalls)
			}
		})
	}
}

func TestScanCIDRAllowsAndCanonicalizesPrivateAndLinkLocalNetworks(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "192.168.20.42/24", want: "192.168.20.0/24"},
		{input: "169.254.10.42/24", want: "169.254.10.0/24"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			var commandArgs []string
			service := newNmapHelperServiceWithOptions(t, "hosts", Options{}, func(args []string) {
				commandArgs = append([]string(nil), args...)
			})

			result, err := service.ScanCIDR(context.Background(), test.input)
			if err != nil {
				t.Fatalf("ScanCIDR returned error: %v", err)
			}
			if result.CIDR != test.want {
				t.Fatalf("result CIDR = %q, want %q", result.CIDR, test.want)
			}
			assertIPs(t, result.ScannedCIDRs, []string{test.want})
			if got := commandArgs[len(commandArgs)-1]; got != test.want {
				t.Fatalf("nmap target = %q, want %q", got, test.want)
			}
		})
	}
}

func TestScanCIDRAllowsPublicNetworkOnlyWithExplicitOption(t *testing.T) {
	var commandArgs []string
	service := newNmapHelperServiceWithOptions(t, "hosts", Options{AllowPublicNetworks: true}, func(args []string) {
		commandArgs = append([]string(nil), args...)
	})

	result, err := service.ScanCIDR(context.Background(), "203.0.113.42/24")
	if err != nil {
		t.Fatalf("ScanCIDR returned error: %v", err)
	}
	if result.CIDR != "203.0.113.0/24" {
		t.Fatalf("result CIDR = %q, want %q", result.CIDR, "203.0.113.0/24")
	}
	if got := commandArgs[len(commandArgs)-1]; got != "203.0.113.0/24" {
		t.Fatalf("nmap target = %q, want %q", got, "203.0.113.0/24")
	}
}

func assertIPs(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func newNmapHelperService(t *testing.T, mode string, onCommand func([]string)) *Service {
	t.Helper()
	return newNmapHelperServiceWithOptions(t, mode, Options{AllowPublicNetworks: true}, onCommand)
}

func newNmapHelperServiceWithOptions(t *testing.T, mode string, options Options, onCommand func([]string)) *Service {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test executable: %v", err)
	}

	options.NmapPath = executable
	service := NewServiceWithOptions(options)
	service.commandContext = func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		if onCommand != nil {
			onCommand(args)
		}
		helperArgs := []string{"-test.run=TestNmapHelperProcess", "--"}
		helperArgs = append(helperArgs, args...)
		command := exec.CommandContext(ctx, executable, helperArgs...)
		command.Env = append(os.Environ(),
			"HOME_MESH_NMAP_HELPER=1",
			"HOME_MESH_NMAP_HELPER_MODE="+mode,
		)
		return command
	}
	return service
}

func TestNmapHelperProcess(t *testing.T) {
	if os.Getenv("HOME_MESH_NMAP_HELPER") != "1" {
		return
	}

	switch os.Getenv("HOME_MESH_NMAP_HELPER_MODE") {
	case "hosts":
		fmt.Print(`<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="192.0.2.11" addrtype="ipv4"/></host>
  <host>
    <status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:10" addrtype="mac" vendor="Example Vendor"/>
    <hostnames><hostname name="host-10.example" type="PTR"/></hostnames>
  </host>
  <host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/></host>
</nmaprun>
`)
	case "block":
		time.Sleep(time.Minute)
	case "exit-silent":
		os.Exit(1)
	case "exit-stderr":
		fmt.Fprintln(os.Stderr, "simulated nmap failure")
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "unknown helper mode")
		os.Exit(2)
	}
	os.Exit(0)
}
