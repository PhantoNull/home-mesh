package discovery

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

var (
	ErrNmapUnavailable   = errors.New("nmap is not available")
	ErrScanInProgress    = errors.New("discovery scan already in progress")
	ErrNetworkNotAllowed = errors.New("discovery network is not private or link-local")
	errNmapCompletion    = errors.New("nmap XML did not report successful completion")
)

type Options struct {
	NmapPath            string
	AllowPublicNetworks bool
}

type Service struct {
	nmapPath            string
	allowPublicNetworks bool
	scanning            atomic.Bool
	commandContext      func(context.Context, string, ...string) *exec.Cmd
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

type nmapXMLHost struct {
	Status    nmapXMLStatus    `xml:"status"`
	Addresses []nmapXMLAddress `xml:"address"`
	Hostnames nmapXMLHostnames `xml:"hostnames"`
}

type nmapXMLStatus struct {
	State string `xml:"state,attr"`
}

type nmapXMLAddress struct {
	Address string `xml:"addr,attr"`
	Type    string `xml:"addrtype,attr"`
	Vendor  string `xml:"vendor,attr"`
}

type nmapXMLHostnames struct {
	Names []nmapXMLHostname `xml:"hostname"`
}

type nmapXMLHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapXMLRunStats struct {
	Finished nmapXMLFinished `xml:"finished"`
}

type nmapXMLFinished struct {
	Exit     string `xml:"exit,attr"`
	ErrorMsg string `xml:"errormsg,attr"`
}

func NewService(nmapPath string) *Service {
	return NewServiceWithOptions(Options{NmapPath: nmapPath})
}

func NewServiceWithOptions(options Options) *Service {
	path := strings.TrimSpace(options.NmapPath)
	if path == "" {
		path = "nmap"
	}

	return &Service{
		nmapPath:            path,
		allowPublicNetworks: options.AllowPublicNetworks,
		commandContext:      exec.CommandContext,
	}
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
		canonicalCIDR, err := canonicalScanCIDR(trimmedCIDR, s.allowPublicNetworks)
		if err != nil {
			return ScanResult{}, fmt.Errorf("invalid CIDR: %w", err)
		}
		targetCIDRs = append(targetCIDRs, canonicalCIDR)
	} else {
		var err error
		targetCIDRs, err = suggestedIPv4CIDRs()
		if err != nil {
			return ScanResult{}, fmt.Errorf("failed to detect local networks: %w", err)
		}
		if len(targetCIDRs) == 0 {
			return ScanResult{}, errors.New("no suitable local IPv4 networks were detected")
		}
		for index, targetCIDR := range targetCIDRs {
			canonicalCIDR, err := canonicalScanCIDR(targetCIDR, s.allowPublicNetworks)
			if err != nil {
				return ScanResult{}, fmt.Errorf("unsupported detected network %s: %w", targetCIDR, err)
			}
			targetCIDRs[index] = canonicalCIDR
		}
	}

	if !s.scanning.CompareAndSwap(false, true) {
		return ScanResult{}, ErrScanInProgress
	}
	defer s.scanning.Store(false)

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
	} else {
		displayCIDR = targetCIDRs[0]
	}

	return ScanResult{
		Provider:     "nmap",
		CIDR:         displayCIDR,
		ScannedCIDRs: targetCIDRs,
		Hosts:        hosts,
	}, nil
}

func canonicalScanCIDR(cidr string, allowPublicNetworks bool) (string, error) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", err
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return "", errors.New("only IPv4 CIDRs are supported")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return "", errors.New("only IPv4 CIDRs are supported")
	}
	if ones < 16 {
		return "", errors.New("CIDR prefix must be /16 or more specific")
	}

	networkIP := ipv4.Mask(network.Mask)
	canonicalCIDR := fmt.Sprintf("%s/%d", networkIP.String(), ones)
	if !allowPublicNetworks && !isPrivateOrLinkLocalIPv4(networkIP) {
		return "", fmt.Errorf("%w: %s", ErrNetworkNotAllowed, canonicalCIDR)
	}
	return canonicalCIDR, nil
}

func isPrivateOrLinkLocalIPv4(ip net.IP) bool {
	ipv4 := ip.To4()
	return ipv4 != nil && (ipv4.IsPrivate() || ipv4.IsLinkLocalUnicast())
}

func (s *Service) scanTargetCIDR(ctx context.Context, targetCIDR string, hostsByIP map[string]HostMatch, onHost func(HostMatch) error) error {
	commandContext := s.commandContext
	if commandContext == nil {
		commandContext = exec.CommandContext
	}
	cmd := commandContext(
		ctx,
		s.nmapPath,
		"-sn",
		"-PE",
		"-PS22,80,443",
		"-PA22,80,443",
		"-PU53",
		"-oX",
		"-",
		targetCIDR,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("nmap stdout pipe failed for %s: %w", targetCIDR, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("nmap stderr pipe failed for %s: %w", targetCIDR, err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("nmap start failed for %s: %w", targetCIDR, err)
	}

	var stderrBuffer bytes.Buffer
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		_, _ = io.Copy(&stderrBuffer, stderr)
	}()

	emit := func(host HostMatch) error {
		ipAddress := strings.TrimSpace(host.IPAddress)
		if ipAddress == "" {
			return nil
		}
		if existing, exists := hostsByIP[ipAddress]; exists {
			hostsByIP[ipAddress] = mergeHostMatch(existing, host)
			return nil
		}
		hostsByIP[ipAddress] = host
		if onHost != nil {
			return onHost(host)
		}
		return nil
	}

	if err := scanNmapXMLStream(stdout, emit); err != nil {
		if errors.Is(err, errNmapCompletion) {
			<-stderrDone
			if waitErr := cmd.Wait(); waitErr != nil {
				return nmapProcessError(ctx, targetCIDR, waitErr, stderrBuffer.String())
			}
			return err
		}
		_ = cmd.Process.Kill()
		<-stderrDone
		_ = cmd.Wait()
		return err
	}
	<-stderrDone
	if err := cmd.Wait(); err != nil {
		return nmapProcessError(ctx, targetCIDR, err, stderrBuffer.String())
	}

	return nil
}

func nmapProcessError(ctx context.Context, targetCIDR string, processErr error, stderr string) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("nmap scan canceled for %s: %w", targetCIDR, ctxErr)
	}
	if stderr = strings.TrimSpace(stderr); stderr != "" {
		return fmt.Errorf("nmap scan failed for %s: %w: %s", targetCIDR, processErr, stderr)
	}
	return fmt.Errorf("nmap scan failed for %s: %w", targetCIDR, processErr)
}

func scanNmapXMLStream(reader io.Reader, emit func(HostMatch) error) error {
	decoder := xml.NewDecoder(reader)
	rootSeen := false
	runStatsSeen := false
	var finished nmapXMLFinished
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			switch {
			case !rootSeen:
				return fmt.Errorf("%w: missing nmaprun document", errNmapCompletion)
			case !runStatsSeen || strings.TrimSpace(finished.Exit) == "":
				return fmt.Errorf("%w: missing runstats finished exit=success", errNmapCompletion)
			case strings.TrimSpace(finished.Exit) != "success":
				message := strings.TrimSpace(finished.ErrorMsg)
				if message == "" {
					return fmt.Errorf("%w: nmap reported exit=%s", errNmapCompletion, strings.TrimSpace(finished.Exit))
				}
				return fmt.Errorf("%w: nmap reported exit=%s: %s", errNmapCompletion, strings.TrimSpace(finished.Exit), message)
			default:
				return nil
			}
		}
		if err != nil {
			return fmt.Errorf("parse nmap XML: %w", err)
		}

		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !rootSeen {
			if start.Name.Local != "nmaprun" {
				return fmt.Errorf("parse nmap XML: expected nmaprun root, got %s", start.Name.Local)
			}
			rootSeen = true
			continue
		}

		switch start.Name.Local {
		case "host":
			var xmlHost nmapXMLHost
			if err := decoder.DecodeElement(&xmlHost, &start); err != nil {
				return fmt.Errorf("parse nmap XML host: %w", err)
			}
			host, ok := hostMatchFromXML(xmlHost)
			if !ok {
				continue
			}
			if err := emit(host); err != nil {
				return err
			}
		case "runstats":
			if runStatsSeen {
				return fmt.Errorf("parse nmap XML: duplicate runstats")
			}
			var runStats nmapXMLRunStats
			if err := decoder.DecodeElement(&runStats, &start); err != nil {
				return fmt.Errorf("parse nmap XML runstats: %w", err)
			}
			runStatsSeen = true
			finished = runStats.Finished
		}
	}
}

func hostMatchFromXML(xmlHost nmapXMLHost) (HostMatch, bool) {
	if !strings.EqualFold(strings.TrimSpace(xmlHost.Status.State), "up") {
		return HostMatch{}, false
	}

	host := HostMatch{}
	for _, address := range xmlHost.Addresses {
		switch strings.ToLower(strings.TrimSpace(address.Type)) {
		case "ipv4":
			ipAddress := net.ParseIP(strings.TrimSpace(address.Address)).To4()
			if ipAddress != nil {
				host.IPAddress = ipAddress.String()
			}
		case "mac":
			macAddress, err := net.ParseMAC(strings.TrimSpace(address.Address))
			if err == nil && len(macAddress) == 6 {
				host.MACAddress = strings.ToUpper(macAddress.String())
				host.Vendor = strings.TrimSpace(address.Vendor)
			}
		}
	}
	if host.IPAddress == "" {
		return HostMatch{}, false
	}

	for _, hostname := range xmlHost.Hostnames.Names {
		name, ok := canonicalObservedHostname(hostname.Name)
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(hostname.Type), "PTR") {
			host.Hostname = name
			break
		}
		if host.Hostname == "" {
			host.Hostname = name
		}
	}

	return host, true
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

func mergeHostMatch(existing HostMatch, current HostMatch) HostMatch {
	if current.Hostname == "" {
		current.Hostname = existing.Hostname
	}
	if current.MACAddress == "" {
		current.MACAddress = existing.MACAddress
	}
	if current.Vendor == "" {
		current.Vendor = existing.Vendor
	}
	if len(current.OpenPorts) == 0 {
		current.OpenPorts = existing.OpenPorts
	}
	if len(current.Tags) == 0 {
		current.Tags = existing.Tags
	}
	return current
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
			var cidr string
			if suggestedOnly {
				var valid bool
				cidr, valid = suggestedIPv4CIDR(ipv4, ipNet.Mask)
				if !valid {
					continue
				}
			} else {
				ones, bits := ipNet.Mask.Size()
				if bits != 32 || ones <= 0 || ones > 30 {
					continue
				}
				cidr = fmt.Sprintf("%s/%d", ipv4.Mask(ipNet.Mask).String(), ones)
			}
			if !seen[cidr] {
				seen[cidr] = true
				cidrs = append(cidrs, cidr)
			}
		}
	}

	sort.Strings(cidrs)
	return cidrs, nil
}

func suggestedIPv4CIDR(ip net.IP, mask net.IPMask) (string, bool) {
	ipv4 := ip.To4()
	ones, bits := mask.Size()
	if ipv4 == nil || bits != 32 || ones <= 0 || ones > 30 || !isPrivateOrLinkLocalIPv4(ipv4) {
		return "", false
	}

	if ones < 24 {
		ones = 24
		mask = net.CIDRMask(ones, bits)
	}
	return fmt.Sprintf("%s/%d", ipv4.Mask(mask).String(), ones), true
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

func DefaultNmapPath() string {
	if runtime.GOOS == "windows" {
		return "nmap.exe"
	}
	return "nmap"
}
