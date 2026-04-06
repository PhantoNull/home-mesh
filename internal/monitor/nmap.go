package monitor

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// nmapScanResult holds the probed state of a single host returned by nmap.
type nmapScanResult struct {
	IP        string
	Up        bool
	MAC       string
	Vendor    string
	Hostname  string
	OpenPorts []int
}

// --- XML structs matching nmap's -oX output ---

type nmapXMLRun struct {
	XMLName xml.Name     `xml:"nmaprun"`
	Hosts   []nmapXMLHost `xml:"host"`
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
	Protocol string          `xml:"protocol,attr"`
	PortID   string          `xml:"portid,attr"`
	State    nmapXMLPortState `xml:"state"`
}

type nmapXMLPortState struct {
	State string `xml:"state,attr"`
}

// nmapDetect returns the path to nmap if it is installed, or an empty string.
func nmapDetect() string {
	path, err := exec.LookPath("nmap")
	if err != nil {
		return ""
	}
	return path
}

// nmapScan runs a single nmap process over ips with the given ports and returns
// a map keyed by IPv4 address. Hosts that did not respond are absent from the map.
//
// The scan uses TCP connect (-sT) which requires no elevated privileges.
// Timing template -T4 is aggressive but well-behaved on local networks.
func nmapScan(ctx context.Context, nmapPath string, ips []string, ports []int) (map[string]nmapScanResult, error) {
	if len(ips) == 0 {
		return map[string]nmapScanResult{}, nil
	}

	args := []string{
		"-sT",               // TCP connect — no root required
		"-T4",               // aggressive timing
		"--host-timeout", "6s",
		"--open",            // only report open ports
		"-oX", "-",          // XML to stdout
	}
	if portList := joinPorts(ports); portList != "" {
		args = append(args, "-p", portList)
	}
	args = append(args, ips...)

	out, err := exec.CommandContext(ctx, nmapPath, args...).Output()
	if err != nil {
		// nmap exits non-zero when no hosts are up; still parse what we have.
		if len(out) == 0 {
			return map[string]nmapScanResult{}, fmt.Errorf("nmap: %w", err)
		}
	}

	return parseNmapXML(out)
}

// nmapScanOne is a convenience wrapper for probing a single IP.
func nmapScanOne(ctx context.Context, nmapPath string, ip string, ports []int) nmapScanResult {
	results, err := nmapScan(ctx, nmapPath, []string{ip}, ports)
	if err != nil || len(results) == 0 {
		return nmapScanResult{IP: ip, Up: false}
	}
	result, ok := results[ip]
	if !ok {
		return nmapScanResult{IP: ip, Up: false}
	}
	return result
}

func parseNmapXML(data []byte) (map[string]nmapScanResult, error) {
	var run nmapXMLRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}

	results := make(map[string]nmapScanResult, len(run.Hosts))
	for _, host := range run.Hosts {
		result := nmapScanResult{Up: host.Status.State == "up"}

		for _, addr := range host.Addresses {
			switch addr.AddrType {
			case "ipv4":
				result.IP = addr.Addr
			case "mac":
				result.MAC = strings.ToUpper(addr.Addr)
				result.Vendor = addr.Vendor
			}
		}
		if result.IP == "" {
			continue
		}

		for _, hn := range host.Hostnames.List {
			if hn.Type == "PTR" || result.Hostname == "" {
				result.Hostname = strings.TrimSuffix(hn.Name, ".")
				if hn.Type == "PTR" {
					break
				}
			}
		}

		for _, port := range host.Ports.List {
			if port.State.State == "open" && port.Protocol == "tcp" {
				if n, err := strconv.Atoi(port.PortID); err == nil {
					result.OpenPorts = append(result.OpenPorts, n)
				}
			}
		}

		results[result.IP] = result
	}

	return results, nil
}

func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// allCandidatePorts returns the union of ports used across all device/node types.
// Used for batch scans where we don't know device types in advance.
func allCandidatePorts() []int {
	seen := map[int]bool{}
	var ports []int
	for _, p := range []int{22, 53, 80, 139, 161, 443, 445, 2049, 5000, 5001, 5985, 5986} {
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return ports
}
