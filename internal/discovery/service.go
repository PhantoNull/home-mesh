package discovery

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

var ErrNmapUnavailable = errors.New("nmap is not available")

const discoveryBatchSize = 32

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
	return s.scanCIDR(ctx, cidr, nil)
}

func (s *Service) ScanCIDRStream(ctx context.Context, cidr string, onHost func(HostMatch) error) (ScanResult, error) {
	return s.scanCIDR(ctx, cidr, onHost)
}

func (s *Service) scanCIDR(ctx context.Context, cidr string, onHost func(HostMatch) error) (ScanResult, error) {
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
		if err := s.scanTargetCIDR(ctx, targetCIDR, hostsByIP, onHost); err != nil {
			return ScanResult{}, err
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

func (s *Service) scanTargetCIDR(ctx context.Context, targetCIDR string, hostsByIP map[string]HostMatch, onHost func(HostMatch) error) error {
	targets, err := expandIPv4Targets(targetCIDR)
	if err != nil {
		return fmt.Errorf("expand targets for %s: %w", targetCIDR, err)
	}
	if len(targets) == 0 {
		return nil
	}

	for _, batch := range chunkStrings(targets, discoveryBatchSize) {
		if err := s.scanTargets(ctx, batch, targetCIDR, hostsByIP, onHost); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) scanTargets(ctx context.Context, targets []string, targetLabel string, hostsByIP map[string]HostMatch, onHost func(HostMatch) error) error {
	if len(targets) == 0 {
		return nil
	}

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
	)
	cmd.Args = append(cmd.Args, targets...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("nmap stdout pipe failed for %s: %w", targetLabel, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("nmap stderr pipe failed for %s: %w", targetLabel, err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("nmap start failed for %s: %w", targetLabel, err)
	}

	var stderrBuffer bytes.Buffer
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		_, _ = io.Copy(&stderrBuffer, stderr)
	}()

	emittedHosts := 0
	emit := func(host HostMatch) error {
		if strings.TrimSpace(host.IPAddress) == "" {
			return nil
		}
		hostsByIP[host.IPAddress] = host
		emittedHosts++
		if onHost != nil {
			return onHost(host)
		}
		return nil
	}

	if err := scanNmapPingStream(stdout, emit); err != nil {
		_ = cmd.Process.Kill()
		<-stderrDone
		_ = cmd.Wait()
		return err
	}
	<-stderrDone
	if err := cmd.Wait(); err != nil {
		if isIgnorableNmapExit(err, stderrBuffer.String(), emittedHosts) {
			return nil
		}
		return fmt.Errorf("nmap scan failed for %s: %w", targetLabel, err)
	}

	return nil
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
	hosts := make([]HostMatch, 0)
	_ = scanNmapPingStream(bytes.NewReader(output), func(host HostMatch) error {
		hosts = append(hosts, host)
		return nil
	})
	return hosts
}

func scanNmapPingStream(reader io.Reader, emit func(HostMatch) error) error {
	scanner := bufio.NewScanner(reader)
	var current *HostMatch
	currentUp := false

	flush := func() error {
		if current == nil || !currentUp || strings.TrimSpace(current.IPAddress) == "" {
			current = nil
			currentUp = false
			return nil
		}
		host := *current
		current = nil
		currentUp = false
		return emit(host)
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Nmap scan report for ") {
			if err := flush(); err != nil {
				return err
			}
			target := strings.TrimPrefix(line, "Nmap scan report for ")
			current = &HostMatch{}
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
	if err := scanner.Err(); err != nil {
		return err
	}
	return flush()
}

func DefaultNmapPath() string {
	if runtime.GOOS == "windows" {
		return "nmap.exe"
	}
	return "nmap"
}

func expandIPv4Targets(cidr string) ([]string, error) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, err
	}

	start := ip.To4()
	if start == nil {
		return nil, errors.New("only IPv4 CIDRs are supported")
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, errors.New("only IPv4 CIDRs are supported")
	}
	if ones < 16 {
		return nil, errors.New("CIDR is too large; use /16 or smaller")
	}

	networkIP := network.IP.Mask(network.Mask).To4()
	if networkIP == nil {
		return nil, errors.New("invalid IPv4 network")
	}

	broadcast := make(net.IP, len(networkIP))
	copy(broadcast, networkIP)
	for i := range broadcast {
		broadcast[i] |= ^network.Mask[i]
	}

	targets := make([]string, 0)
	for current := append(net.IP(nil), networkIP...); compareIPStrings(current.String(), broadcast.String()) <= 0; incrementIPv4(current) {
		target := current.String()
		if target == networkIP.String() || target == broadcast.String() {
			continue
		}
		targets = append(targets, target)
	}

	if len(targets) == 0 {
		targets = append(targets, networkIP.String())
	}

	return targets, nil
}

func incrementIPv4(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func chunkStrings(values []string, size int) [][]string {
	if size <= 0 || len(values) == 0 {
		return nil
	}

	chunks := make([][]string, 0, (len(values)+size-1)/size)
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		chunks = append(chunks, values[start:end])
	}
	return chunks
}

func isIgnorableNmapExit(err error, stderr string, emittedHosts int) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	if exitErr.ExitCode() != 1 {
		return false
	}

	trimmedStderr := strings.TrimSpace(stderr)
	if trimmedStderr != "" {
		return false
	}

	return true
}
