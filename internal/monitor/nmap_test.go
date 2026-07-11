package monitor

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestNmapArgumentsDoNotFilterHostsWithoutOpenPorts(t *testing.T) {
	t.Parallel()

	arguments := nmapArguments([]string{"192.168.1.10"}, []int{443, 80, 443, 0, 70000})
	if slices.Contains(arguments, "--open") {
		t.Fatalf("arguments unexpectedly contain --open: %v", arguments)
	}
	portIndex := slices.Index(arguments, "-p")
	if portIndex < 0 || portIndex+1 >= len(arguments) || arguments[portIndex+1] != "80,443" {
		t.Fatalf("port argument = %v", arguments)
	}
}

func TestParseNmapXMLKeepsUpHostWithoutOpenPorts(t *testing.T) {
	t.Parallel()

	results, err := parseNmapXML([]byte(`
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.168.1.10" addrtype="ipv4" />
    <ports><port protocol="tcp" portid="22"><state state="closed" /></port></ports>
  </host>
  <runstats><finished exit="success" /></runstats>
</nmaprun>`))
	if err != nil {
		t.Fatal(err)
	}
	result, exists := results["192.168.1.10"]
	if !exists || !result.Up {
		t.Fatalf("result = %#v, exists=%t", result, exists)
	}
	if len(result.OpenPorts) != 0 {
		t.Fatalf("open ports = %v", result.OpenPorts)
	}
}

func TestParseNmapXMLRejectsFailedRun(t *testing.T) {
	t.Parallel()

	_, err := parseNmapXML([]byte(`<nmaprun><runstats><finished exit="error" errormsg="bad target" /></runstats></nmaprun>`))
	if err == nil || !strings.Contains(err.Error(), "bad target") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseNmapXMLRequiresCompleteSuccessfulRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
	}{
		{name: "empty", xml: ""},
		{name: "truncated", xml: `<nmaprun><host><status state="up"/></host>`},
		{name: "missing runstats", xml: `<nmaprun><host><status state="up"/></host></nmaprun>`},
		{name: "missing finished", xml: `<nmaprun><runstats/></nmaprun>`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseNmapXML([]byte(test.xml)); err == nil {
				t.Fatal("parseNmapXML returned nil error")
			}
		})
	}
}

func TestParseNmapXMLCanonicalizesAndDiscardsInvalidHostnames(t *testing.T) {
	t.Parallel()

	results, err := parseNmapXML([]byte(`
<nmaprun>
  <host>
    <status state="up" />
    <address addr="192.0.2.10" addrtype="ipv4" />
    <hostnames>
      <hostname name="Fallback.EXAMPLE." type="user" />
      <hostname name="bad_name" type="PTR" />
    </hostnames>
  </host>
  <host>
    <status state="up" />
    <address addr="192.0.2.11" addrtype="ipv4" />
    <hostnames><hostname name="192.0.2.99" type="PTR" /></hostnames>
  </host>
  <runstats><finished exit="success" /></runstats>
</nmaprun>`))
	if err != nil {
		t.Fatal(err)
	}
	if got := results["192.0.2.10"].Hostname; got != "fallback.example" {
		t.Fatalf("canonical hostname = %q", got)
	}
	if got := results["192.0.2.11"].Hostname; got != "" {
		t.Fatalf("invalid PTR hostname = %q", got)
	}
}

func TestCanonicalIPv4RejectsCommandOptionsAndNormalizesMappedAddress(t *testing.T) {
	t.Parallel()

	if _, err := canonicalIPv4("--script=unsafe"); err == nil {
		t.Fatal("command option was accepted as an IP address")
	}
	canonical, err := canonicalIPv4("::ffff:192.168.1.8")
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "192.168.1.8" {
		t.Fatalf("canonical address = %q", canonical)
	}
}

func TestNmapScanOneDoesNotConvertScannerFailureToOffline(t *testing.T) {
	t.Parallel()

	wantErr := context.DeadlineExceeded
	_, err := nmapScanOne(context.Background(), func(context.Context, string, []string, []int) (map[string]nmapScanResult, error) {
		return nil, wantErr
	}, "nmap", "192.168.1.2", []int{22})
	if err != wantErr {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}
