package monitor

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/PhantoNull/home-mesh/internal/networkscan"
)

const (
	nmapStdoutLimit = 8 * 1024 * 1024
	nmapStderrLimit = 64 * 1024
)

type nmapScanResult struct {
	IP        string
	Up        bool
	MAC       string
	Vendor    string
	Hostname  string
	OpenPorts []int
}

type nmapCommandOutput struct {
	stdout *networkscan.BoundedBuffer
	stderr *networkscan.BoundedBuffer
}

type nmapXMLRun struct {
	XMLName  xml.Name        `xml:"nmaprun"`
	Hosts    []nmapXMLHost   `xml:"host"`
	RunStats nmapXMLRunStats `xml:"runstats"`
}

type nmapXMLRunStats struct {
	Finished nmapXMLFinished `xml:"finished"`
}

type nmapXMLFinished struct {
	Exit     string `xml:"exit,attr"`
	ErrorMsg string `xml:"errormsg,attr"`
}

type nmapXMLHost struct {
	Status    nmapXMLStatus    `xml:"status"`
	Addresses []nmapXMLAddress `xml:"address"`
	Hostnames nmapXMLHostnames `xml:"hostnames"`
	Ports     nmapXMLPorts     `xml:"ports"`
}

type nmapXMLStatus struct {
	State string `xml:"state,attr"`
}

type nmapXMLAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type nmapXMLHostnames struct {
	List []nmapXMLHostname `xml:"hostname"`
}

type nmapXMLHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapXMLPorts struct {
	List []nmapXMLPort `xml:"port"`
}

type nmapXMLPort struct {
	Protocol string           `xml:"protocol,attr"`
	PortID   string           `xml:"portid,attr"`
	State    nmapXMLPortState `xml:"state"`
}

type nmapXMLPortState struct {
	State string `xml:"state,attr"`
}

func nmapDetect() string {
	path, err := exec.LookPath("nmap")
	if err != nil {
		return ""
	}
	return path
}

// nmapScan runs one bounded process for a canonicalized set of IPv4 targets.
// It deliberately does not use --open: hosts without an open candidate port
// must remain visible so they are not mistaken for hosts that were never seen.
func nmapScan(ctx context.Context, nmapPath string, ips []string, ports []int) (map[string]nmapScanResult, error) {
	if len(ips) == 0 {
		return map[string]nmapScanResult{}, nil
	}

	canonicalIPs, err := canonicalIPv4List(ips)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(nmapPath) == "" {
		return nil, fmt.Errorf("nmap path is empty")
	}

	// #nosec G204 -- the executable is resolved from administrator configuration;
	// every dynamic target is a parsed IPv4 literal and ports are numeric.
	cmd := exec.CommandContext(ctx, nmapPath, nmapArguments(canonicalIPs, ports)...)
	output, err := runNmapCommand(cmd)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("nmap failed: %w: %s", err, boundedMessage(output.stderr.String(), 512))
	}
	if output.stdout.Truncated() {
		return nil, fmt.Errorf("nmap XML output exceeded %d bytes", nmapStdoutLimit)
	}

	return parseNmapXML(output.stdout.Bytes())
}

func runNmapCommand(cmd *exec.Cmd) (nmapCommandOutput, error) {
	output := nmapCommandOutput{
		stdout: networkscan.NewBoundedBuffer(nmapStdoutLimit),
		stderr: networkscan.NewBoundedBuffer(nmapStderrLimit),
	}
	cmd.Stdout = output.stdout
	cmd.Stderr = output.stderr
	return output, cmd.Run()
}

func nmapArguments(ips []string, ports []int) []string {
	args := []string{
		"-sT",
		"-T4",
		"-PS22,80,443",
		"-PA22,80,443",
		"-oX", "-",
	}
	if portList := joinPorts(ports); portList != "" {
		args = append(args, "-p", portList)
	}
	return append(args, ips...)
}

// A missing result after a successful process is a conclusive unreachable
// result. Process and XML errors stay distinct so callers can use real probes.
func nmapScanOne(ctx context.Context, scan func(context.Context, string, []string, []int) (map[string]nmapScanResult, error), nmapPath string, ip string, ports []int) (nmapScanResult, error) {
	canonicalIP, err := canonicalIPv4(ip)
	if err != nil {
		return nmapScanResult{}, err
	}
	results, err := scan(ctx, nmapPath, []string{canonicalIP}, ports)
	if err != nil {
		return nmapScanResult{}, err
	}
	result, ok := results[canonicalIP]
	if !ok {
		return nmapScanResult{IP: canonicalIP}, nil
	}
	return result, nil
}

func parseNmapXML(data []byte) (map[string]nmapScanResult, error) {
	var run nmapXMLRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}
	exit := strings.TrimSpace(run.RunStats.Finished.Exit)
	if exit == "" {
		return nil, fmt.Errorf("nmap XML is incomplete: missing runstats finished exit=success")
	}
	if exit != "success" {
		message := strings.TrimSpace(run.RunStats.Finished.ErrorMsg)
		if message == "" {
			return nil, fmt.Errorf("nmap reported exit=%s", exit)
		}
		return nil, fmt.Errorf("nmap reported exit=%s: %s", exit, message)
	}

	results := make(map[string]nmapScanResult, len(run.Hosts))
	for _, host := range run.Hosts {
		result := nmapScanResult{Up: host.Status.State == "up"}

		for _, address := range host.Addresses {
			switch address.AddrType {
			case "ipv4":
				result.IP = address.Addr
			case "mac":
				result.MAC = strings.ToUpper(address.Addr)
				result.Vendor = address.Vendor
			}
		}
		if result.IP == "" {
			continue
		}

		for _, hostname := range host.Hostnames.List {
			name, ok := canonicalObservedHostname(hostname.Name)
			if !ok {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(hostname.Type), "PTR") {
				result.Hostname = name
				break
			}
			if result.Hostname == "" {
				result.Hostname = name
			}
		}

		for _, port := range host.Ports.List {
			if port.State.State == "open" && port.Protocol == "tcp" {
				if number, err := strconv.Atoi(port.PortID); err == nil {
					result.OpenPorts = append(result.OpenPorts, number)
				}
			}
		}

		if normalized, ok := normalizeNmapResult(result); ok {
			results[normalized.IP] = normalized
		}
	}

	return results, nil
}

func normalizeNmapResult(result nmapScanResult) (nmapScanResult, bool) {
	canonicalIP, err := canonicalIPv4(result.IP)
	if err != nil {
		return nmapScanResult{}, false
	}
	result.IP = canonicalIP
	result.MAC = strings.ToUpper(strings.TrimSpace(result.MAC))
	if hostname, ok := canonicalObservedHostname(result.Hostname); ok {
		result.Hostname = hostname
	} else {
		result.Hostname = ""
	}
	validPorts := result.OpenPorts[:0]
	for _, port := range result.OpenPorts {
		if port >= 1 && port <= 65535 {
			validPorts = append(validPorts, port)
		}
	}
	result.OpenPorts = validPorts
	slices.Sort(result.OpenPorts)
	result.OpenPorts = slices.Compact(result.OpenPorts)
	return result, true
}

func canonicalObservedHostname(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return "", false
	}
	if address, err := netip.ParseAddr(value); err == nil && address.IsValid() {
		return "", false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", false
			}
		}
	}
	return value, true
}

func canonicalIPv4List(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		canonical, err := canonicalIPv4(value)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result, nil
}

func canonicalIPv4(value string) (string, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q: %w", value, err)
	}
	address = address.Unmap()
	if !address.Is4() {
		return "", fmt.Errorf("IP address %q is not IPv4", value)
	}
	return address.String(), nil
}

func joinPorts(ports []int) string {
	filtered := make([]int, 0, len(ports))
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			continue
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		filtered = append(filtered, port)
	}
	if len(filtered) == 0 {
		return ""
	}

	slices.Sort(filtered)
	parts := make([]string, len(filtered))
	for index, port := range filtered {
		parts[index] = strconv.Itoa(port)
	}
	return strings.Join(parts, ",")
}

func boundedMessage(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func allCandidatePorts() []int {
	return []int{22, 53, 80, 139, 161, 443, 445, 2049, 5000, 5001, 5985, 5986}
}
