package discovery

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

var ErrNmapUnavailable = errors.New("nmap is not available")

type Service struct {
	nmapPath string
}

type Capabilities struct {
	NmapAvailable  bool     `json:"nmapAvailable"`
	NmapPath       string   `json:"nmapPath,omitempty"`
	LocalCIDRs     []string `json:"localCidrs"`
	SuggestedCIDRs []string `json:"suggestedCidrs"`
}

type ScanResult struct {
	Provider     string      `json:"provider"`
	CIDR         string      `json:"cidr"`
	ScannedCIDRs []string    `json:"scannedCidrs"`
	Hosts        []HostMatch `json:"hosts"`
}

type HostMatch struct {
	IPAddress  string   `json:"ipAddress"`
	Hostname   string   `json:"hostname,omitempty"`
	MACAddress string   `json:"macAddress,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
	OpenPorts  []int    `json:"openPorts,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

func NewService(nmapPath string) *Service {
	path := strings.TrimSpace(nmapPath)
	if path == "" {
		path = "nmap"
	}

	return &Service{nmapPath: path}
}

func (s *Service) Capabilities() Capabilities {
	available := s.hasNmap()
	cidrs, _ := localIPv4CIDRs()
	suggestedCIDRs, _ := suggestedIPv4CIDRs()

	result := Capabilities{
		NmapAvailable:  available,
		LocalCIDRs:     cidrs,
		SuggestedCIDRs: suggestedCIDRs,
	}
	if available {
		result.NmapPath = s.nmapPath
	}

	return result
}

func (s *Service) ScanCIDR(ctx context.Context, cidr string) (ScanResult, error) {
	if !s.hasNmap() {
		return ScanResult{}, ErrNmapUnavailable
	}

	trimmedCIDR := strings.TrimSpace(cidr)
	targetCIDRs := []string{}
	if trimmedCIDR != "" {
		if _, _, err := net.ParseCIDR(trimmedCIDR); err != nil {
			return ScanResult{}, fmt.Errorf("invalid CIDR: %w", err)
		}
		targetCIDRs = append(targetCIDRs, trimmedCIDR)
	} else {
		var err error
		targetCIDRs, err = suggestedIPv4CIDRs()
		if err != nil {
			return ScanResult{}, fmt.Errorf("failed to detect local networks: %w", err)
		}
		if len(targetCIDRs) == 0 {
			return ScanResult{}, errors.New("no suitable local IPv4 networks were detected")
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	hostsByIP := make(map[string]HostMatch)
	for _, targetCIDR := range targetCIDRs {
		cmd := exec.CommandContext(
			ctx,
			s.nmapPath,
			"-sn",
			"-n",
			"--disable-arp-ping",
			"-PE",
			"-PS22,80,443",
			"-PA22,80,443",
			"-PU53",
			targetCIDR,
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return ScanResult{}, fmt.Errorf("nmap scan failed for %s: %w", targetCIDR, err)
		}

		for _, host := range parseNmapPingScan(output) {
			if strings.TrimSpace(host.IPAddress) == "" {
				continue
			}
			hostsByIP[host.IPAddress] = host
		}
	}

	hosts := make([]HostMatch, 0, len(hostsByIP))
	for _, host := range hostsByIP {
		hosts = append(hosts, host)
	}
	sort.Slice(hosts, func(i, j int) bool {
		return compareIPStrings(hosts[i].IPAddress, hosts[j].IPAddress) < 0
	})

	displayCIDR := trimmedCIDR
	if displayCIDR == "" {
		displayCIDR = "auto"
	}

	return ScanResult{
		Provider:     "nmap",
		CIDR:         displayCIDR,
		ScannedCIDRs: targetCIDRs,
		Hosts:        hosts,
	}, nil
}

func (s *Service) hasNmap() bool {
	_, err := exec.LookPath(s.nmapPath)
	return err == nil
}

func localIPv4CIDRs() ([]string, error) {
	return collectIPv4CIDRs(false)
}

func suggestedIPv4CIDRs() ([]string, error) {
	return collectIPv4CIDRs(true)
}

func collectIPv4CIDRs(suggestedOnly bool) ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var cidrs []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if suggestedOnly && !isSuggestedInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			ipv4 := ipNet.IP.To4()
			if ipv4 == nil {
				continue
			}
			if suggestedOnly && !ipv4.IsPrivate() {
				continue
			}
			networkIP := ipv4.Mask(ipNet.Mask)
			ones, bits := ipNet.Mask.Size()
			if bits != 32 || ones <= 0 || ones > 30 {
				continue
			}
			cidr := fmt.Sprintf("%s/%d", networkIP.String(), ones)
			if !seen[cidr] {
				seen[cidr] = true
				cidrs = append(cidrs, cidr)
			}
		}
	}

	sort.Strings(cidrs)
	return cidrs, nil
}

func isSuggestedInterface(name string) bool {
	lowerName := strings.ToLower(strings.TrimSpace(name))
	if lowerName == "" {
		return false
	}

	excluded := []string{
		"docker",
		"veth",
		"br-",
		"tailscale",
		"zt",
		"zerotier",
		"vethernet",
		"wsl",
		"vmware",
		"virtualbox",
		"loopback",
	}
	for _, token := range excluded {
		if strings.Contains(lowerName, token) {
			return false
		}
	}

	return true
}

func compareIPStrings(left string, right string) int {
	leftIP := net.ParseIP(strings.TrimSpace(left)).To4()
	rightIP := net.ParseIP(strings.TrimSpace(right)).To4()

	if leftIP == nil || rightIP == nil {
		return strings.Compare(left, right)
	}

	for index := 0; index < len(leftIP) && index < len(rightIP); index++ {
		if leftIP[index] < rightIP[index] {
			return -1
		}
		if leftIP[index] > rightIP[index] {
			return 1
		}
	}

	return 0
}

func parseNmapPingScan(output []byte) []HostMatch {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	hosts := make([]HostMatch, 0)
	var current *HostMatch
	currentUp := false

	flush := func() {
		if current == nil || !currentUp || strings.TrimSpace(current.IPAddress) == "" {
			return
		}
		hosts = append(hosts, *current)
		current = nil
		currentUp = false
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Nmap scan report for ") {
			flush()
			target := strings.TrimPrefix(line, "Nmap scan report for ")
			current = &HostMatch{}
			currentUp = false
			if open := strings.LastIndex(target, "("); open != -1 && strings.HasSuffix(target, ")") {
				current.Hostname = strings.TrimSpace(target[:open])
				current.IPAddress = strings.TrimSuffix(strings.TrimPrefix(target[open:], "("), ")")
			} else {
				current.IPAddress = strings.TrimSpace(target)
			}
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "Host is up") {
			currentUp = true
			continue
		}
		if strings.HasPrefix(line, "MAC Address: ") {
			macDetails := strings.TrimPrefix(line, "MAC Address: ")
			parts := strings.SplitN(macDetails, " ", 2)
			current.MACAddress = strings.TrimSpace(parts[0])
			if len(parts) > 1 {
				current.Vendor = strings.Trim(strings.TrimSpace(parts[1]), "()")
			}
		}
	}

	flush()
	return hosts
}

func DefaultNmapPath() string {
	if runtime.GOOS == "windows" {
		return "nmap.exe"
	}
	return "nmap"
}
