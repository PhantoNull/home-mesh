package monitor

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PhantoNull/home-mesh/internal/store"
)

var (
	macAddressColonRegex = regexp.MustCompile(`([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}`)
	macAddressDashRegex  = regexp.MustCompile(`([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}`)
)

type RefreshSummary struct {
	Checked     int `json:"checked"`
	Updated     int `json:"updated"`
	Online      int `json:"online"`
	Degraded    int `json:"degraded"`
	Offline     int `json:"offline"`
	MACResolved int `json:"macResolved"`
}

type RefreshResult struct {
	Summary      RefreshSummary      `json:"summary"`
	Devices      []store.Device      `json:"devices"`
	NetworkNodes []store.NetworkNode `json:"networkNodes"`
}

type Refresher struct {
	store    *store.Store
	bus      *EventBus
	nmapPath string
}

const refreshConcurrency = 8

func NewRefresher(inventory *store.Store, bus *EventBus) *Refresher {
	return &Refresher{
		store:    inventory,
		bus:      bus,
		nmapPath: nmapDetect(),
	}
}

// UsingNmap reports whether nmap was detected and will be used for scanning.
func (r *Refresher) UsingNmap() bool { return r.nmapPath != "" }

// RunBackground starts a scan loop that runs until ctx is cancelled.
// Each iteration performs a full batch scan and publishes events.
func (r *Refresher) RunBackground(ctx context.Context, interval time.Duration) {
	log.Printf("background refresh loop started: interval=%s nmap_enabled=%t", interval, r.nmapPath != "")

	// Immediate first scan.
	r.scanAndPublish(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.scanAndPublish(ctx)
		}
	}
}

func (r *Refresher) scanAndPublish(ctx context.Context) {
	devices, err := r.store.ListDevices(ctx)
	if err != nil {
		log.Printf("background refresh: list devices failed: %v", err)
		return
	}
	nodes, err := r.store.ListNetworkNodes(ctx)
	if err != nil {
		log.Printf("background refresh: list network nodes failed: %v", err)
		return
	}

	log.Printf("background refresh: started devices=%d nodes=%d nmap_enabled=%t", len(devices), len(nodes), r.nmapPath != "")

	// Build the started event payload.
	deviceIDs := make([]string, len(devices))
	for i, d := range devices {
		deviceIDs[i] = d.ID
	}
	nodeIDs := make([]string, len(nodes))
	for i, n := range nodes {
		nodeIDs[i] = n.ID
	}
	r.bus.publishJSON(EventScanStarted, map[string]any{
		"deviceIds": deviceIDs,
		"nodeIds":   nodeIDs,
	})

	var updatedDevices []store.Device
	var updatedNodes []store.NetworkNode
	var summary RefreshSummary

	if r.nmapPath != "" {
		var nmapErr error
		updatedDevices, updatedNodes, summary, nmapErr = r.batchScanWithNmap(ctx, devices, nodes)
		if nmapErr != nil {
			log.Printf("background refresh: nmap batch scan failed, falling back to legacy refresh: %v", nmapErr)
			result, err := r.RefreshAll(ctx)
			if err != nil {
				log.Printf("background refresh: fallback refresh failed: %v", err)
				return
			}
			updatedDevices = result.Devices
			updatedNodes = result.NetworkNodes
			summary = result.Summary
		}
	} else {
		result, err := r.RefreshAll(ctx)
		if err != nil {
			log.Printf("background refresh: refresh failed: %v", err)
			return
		}
		updatedDevices = result.Devices
		updatedNodes = result.NetworkNodes
		summary = result.Summary
	}

	for _, d := range updatedDevices {
		r.bus.publishJSON(EventDeviceUpdate, d)
	}
	for _, n := range updatedNodes {
		r.bus.publishJSON(EventNodeUpdate, n)
	}
	r.bus.publishJSON(EventScanComplete, map[string]any{
		"checked":  summary.Checked,
		"updated":  summary.Updated,
		"online":   summary.Online,
		"degraded": summary.Degraded,
		"offline":  summary.Offline,
		"nmapUsed": r.nmapPath != "",
	})
	log.Printf(
		"background refresh: completed checked=%d updated=%d online=%d degraded=%d offline=%d nmap_used=%t",
		summary.Checked,
		summary.Updated,
		summary.Online,
		summary.Degraded,
		summary.Offline,
		r.nmapPath != "",
	)
}

// batchScanWithNmap runs one nmap process over all known IPs and maps results
// back to devices and network nodes.
func (r *Refresher) batchScanWithNmap(ctx context.Context, devices []store.Device, nodes []store.NetworkNode) ([]store.Device, []store.NetworkNode, RefreshSummary, error) {
	// Collect all IPs that are actually scannable.
	type ipEntry struct {
		ip       string
		isDevice bool
		index    int
	}
	var entries []ipEntry
	var ips []string

	for i, d := range devices {
		ip := strings.TrimSpace(d.IPAddress)
		if ip == "" && strings.TrimSpace(d.Hostname) != "" {
			if resolved, err := resolveIPv4(d.Hostname); err == nil {
				ip = resolved
			}
		}
		if ip != "" {
			entries = append(entries, ipEntry{ip: ip, isDevice: true, index: i})
			ips = append(ips, ip)
		}
	}
	for i, n := range nodes {
		ip := strings.TrimSpace(n.ManagementIP)
		if ip != "" {
			entries = append(entries, ipEntry{ip: ip, isDevice: false, index: i})
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		return devices, nodes, RefreshSummary{}, nil
	}

	scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	nmapResults, err := nmapScan(scanCtx, r.nmapPath, ips, allCandidatePorts())
	if err != nil {
		return devices, nodes, RefreshSummary{}, err
	}
	summary := RefreshSummary{Checked: len(entries)}

	for _, entry := range entries {
		nm := nmapResults[entry.ip]

		if entry.isDevice {
			original := devices[entry.index]
			updated := applyNmapToDevice(original, nm)
			updated.IPAddress = entry.ip
			devices[entry.index] = updated
			if persistIfChanged(ctx, r.store, original, updated) {
				summary.Updated++
			}
			switch updated.Status {
			case "online":
				summary.Online++
			case "degraded":
				summary.Degraded++
			default:
				summary.Offline++
			}
		} else {
			original := nodes[entry.index]
			updated := applyNmapToNode(original, nm)
			updated.ManagementIP = entry.ip
			nodes[entry.index] = updated
			if persistNodeIfChanged(ctx, r.store, original, updated) {
				summary.Updated++
			}
			switch updated.Status {
			case "online":
				summary.Online++
			case "degraded":
				summary.Degraded++
			default:
				summary.Offline++
			}
		}
	}

	return devices, nodes, summary, nil
}

func applyNmapToDevice(device store.Device, nm nmapScanResult) store.Device {
	if nm.MAC != "" && nm.MAC != device.MACAddress {
		device.MACAddress = nm.MAC
	}
	if nm.Hostname != "" && device.Hostname == "" {
		device.Hostname = nm.Hostname
	}
	if len(nm.OpenPorts) > 0 {
		if device.Metadata == nil {
			device.Metadata = map[string]string{}
		}
		device.Metadata["lastReachablePorts"] = joinPorts(nm.OpenPorts)
	}

	switch {
	case nm.Up && len(nm.OpenPorts) > 0:
		device.Status = "online"
	case nm.Up:
		device.Status = "online"
	case nm.MAC != "":
		device.Status = "degraded"
	default:
		device.Status = "offline"
	}
	return device
}

func applyNmapToNode(node store.NetworkNode, nm nmapScanResult) store.NetworkNode {
	if nm.MAC != "" && nm.MAC != node.MACAddress {
		node.MACAddress = nm.MAC
	}
	if len(nm.OpenPorts) > 0 {
		if node.Metadata == nil {
			node.Metadata = map[string]string{}
		}
		node.Metadata["lastReachablePorts"] = joinPorts(nm.OpenPorts)
	}
	switch {
	case nm.Up:
		node.Status = "online"
	case nm.MAC != "":
		node.Status = "degraded"
	default:
		node.Status = "offline"
	}
	return node
}

func (r *Refresher) RefreshAll(ctx context.Context) (RefreshResult, error) {
	devices, err := r.store.ListDevices(ctx)
	if err != nil {
		return RefreshResult{}, err
	}
	nodes, err := r.store.ListNetworkNodes(ctx)
	if err != nil {
		return RefreshResult{}, err
	}

	summary := RefreshSummary{}
	refreshedDevices, deviceSummary := r.refreshDevicesParallel(ctx, devices)
	refreshedNodes, nodeSummary := r.refreshNodesParallel(ctx, nodes)
	summary.Checked = deviceSummary.Checked + nodeSummary.Checked
	summary.Updated = deviceSummary.Updated + nodeSummary.Updated
	summary.Online = deviceSummary.Online + nodeSummary.Online
	summary.Degraded = deviceSummary.Degraded + nodeSummary.Degraded
	summary.Offline = deviceSummary.Offline + nodeSummary.Offline
	summary.MACResolved = deviceSummary.MACResolved + nodeSummary.MACResolved

	return RefreshResult{
		Summary:      summary,
		Devices:      refreshedDevices,
		NetworkNodes: refreshedNodes,
	}, nil
}

func (r *Refresher) refreshDevicesParallel(ctx context.Context, devices []store.Device) ([]store.Device, RefreshSummary) {
	type job struct {
		index  int
		device store.Device
	}
	type result struct {
		index       int
		device      store.Device
		updated     bool
		status      string
		macResolved bool
	}

	refreshed := make([]store.Device, len(devices))
	summary := RefreshSummary{Checked: len(devices)}
	if len(devices) == 0 {
		return refreshed, summary
	}

	jobs := make(chan job)
	results := make(chan result, len(devices))
	workers := min(len(devices), refreshConcurrency)
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				device, updated, status, macResolved, err := r.refreshDevice(ctx, job.device)
				if err != nil {
					results <- result{index: job.index, device: job.device, status: "offline"}
					continue
				}
				results <- result{
					index:       job.index,
					device:      device,
					updated:     updated,
					status:      status,
					macResolved: macResolved,
				}
			}
		}()
	}

	go func() {
		for index, device := range devices {
			jobs <- job{index: index, device: device}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for current := range results {
		refreshed[current.index] = current.device
		if current.updated {
			summary.Updated++
		}
		switch current.status {
		case "online":
			summary.Online++
		case "degraded":
			summary.Degraded++
		default:
			summary.Offline++
		}
		if current.macResolved {
			summary.MACResolved++
		}
	}

	return refreshed, summary
}

func (r *Refresher) refreshNodesParallel(ctx context.Context, nodes []store.NetworkNode) ([]store.NetworkNode, RefreshSummary) {
	type job struct {
		index int
		node  store.NetworkNode
	}
	type result struct {
		index       int
		node        store.NetworkNode
		updated     bool
		status      string
		macResolved bool
	}

	refreshed := make([]store.NetworkNode, len(nodes))
	summary := RefreshSummary{Checked: len(nodes)}
	if len(nodes) == 0 {
		return refreshed, summary
	}

	jobs := make(chan job)
	results := make(chan result, len(nodes))
	workers := min(len(nodes), refreshConcurrency)
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				node, updated, status, macResolved, err := r.refreshNetworkNode(ctx, job.node)
				if err != nil {
					results <- result{index: job.index, node: job.node, status: "offline"}
					continue
				}
				results <- result{
					index:       job.index,
					node:        node,
					updated:     updated,
					status:      status,
					macResolved: macResolved,
				}
			}
		}()
	}

	go func() {
		for index, node := range nodes {
			jobs <- job{index: index, node: node}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for current := range results {
		refreshed[current.index] = current.node
		if current.updated {
			summary.Updated++
		}
		switch current.status {
		case "online":
			summary.Online++
		case "degraded":
			summary.Degraded++
		default:
			summary.Offline++
		}
		if current.macResolved {
			summary.MACResolved++
		}
	}

	return refreshed, summary
}

func (r *Refresher) RefreshDeviceByID(ctx context.Context, id string) error {
	device, err := r.store.GetDevice(ctx, id)
	if err != nil {
		return err
	}

	_, _, _, _, err = r.refreshDevice(ctx, device)
	return err
}

func (r *Refresher) RefreshDeviceSnapshotByID(ctx context.Context, id string) (store.Device, error) {
	device, err := r.store.GetDevice(ctx, id)
	if err != nil {
		return store.Device{}, err
	}

	refreshed, _, _, _, err := r.refreshDevice(ctx, device)
	if err != nil {
		return store.Device{}, err
	}

	r.bus.publishJSON(EventDeviceUpdate, refreshed)
	return refreshed, nil
}

func (r *Refresher) RefreshNetworkNodeSnapshotByID(ctx context.Context, id string) (store.NetworkNode, error) {
	node, err := r.store.GetNetworkNode(ctx, id)
	if err != nil {
		return store.NetworkNode{}, err
	}

	refreshed, _, _, _, err := r.refreshNetworkNode(ctx, node)
	if err != nil {
		return store.NetworkNode{}, err
	}

	r.bus.publishJSON(EventNodeUpdate, refreshed)
	return refreshed, nil
}

func (r *Refresher) refreshDevice(ctx context.Context, device store.Device) (store.Device, bool, string, bool, error) {
	if r.nmapPath != "" {
		return r.refreshDeviceWithNmap(ctx, device)
	}
	return r.refreshDeviceFallback(ctx, device)
}

func (r *Refresher) refreshDeviceWithNmap(ctx context.Context, device store.Device) (store.Device, bool, string, bool, error) {
	original := device
	targetIP := strings.TrimSpace(device.IPAddress)

	if strings.TrimSpace(device.Hostname) != "" {
		if resolved, err := resolveIPv4(device.Hostname); err == nil {
			device.IPAddress = resolved
			targetIP = resolved
		}
	}
	if targetIP == "" {
		device.Status = "unknown"
		return device, persistIfChanged(ctx, r.store, original, device), "unknown", false, nil
	}

	nm := nmapScanOne(ctx, r.nmapPath, targetIP, candidatePorts(device))
	device = applyNmapToDevice(device, nm)

	macResolved := nm.MAC != "" && nm.MAC != original.MACAddress
	updated := persistIfChanged(ctx, r.store, original, device)
	return device, updated, device.Status, macResolved, nil
}

func (r *Refresher) refreshDeviceFallback(ctx context.Context, device store.Device) (store.Device, bool, string, bool, error) {
	original := device
	targetIP := strings.TrimSpace(device.IPAddress)
	macResolved := false
	if device.Metadata == nil {
		device.Metadata = map[string]string{}
	}

	if strings.TrimSpace(device.Hostname) != "" {
		if resolvedIP, err := resolveIPv4(device.Hostname); err == nil {
			device.IPAddress = resolvedIP
			targetIP = resolvedIP
		}
	}

	if targetIP == "" {
		device.Status = "unknown"
		return device, persistIfChanged(ctx, r.store, original, device), "unknown", false, nil
	}

	pingOK := pingHost(targetIP, 1500*time.Millisecond)
	tcpOpen := false
	tcpRefused := false
	var openPorts []string
	if !pingOK {
		tcpOpen, tcpRefused, openPorts = probeTCPPorts(targetIP, candidatePorts(device))
	}
	openPorts = mergeOpenPorts(openPorts, probeSelectedPorts(targetIP, 443, 80))
	hasARP := false

	if pingOK || tcpOpen {
		device.Status = "online"

		if device.Hostname == "" {
			if hostname, err := reverseLookup(targetIP); err == nil {
				device.Hostname = hostname
			}
		}

		if macAddress, err := lookupMAC(targetIP); err == nil && macAddress != "" {
			hasARP = true
			if macAddress != device.MACAddress {
				device.MACAddress = macAddress
				macResolved = true
			}
		}
	} else if macAddress, err := lookupMAC(targetIP); err == nil && macAddress != "" {
		hasARP = true
		if device.MACAddress == "" {
			device.MACAddress = macAddress
			macResolved = true
		}
	}

	if len(openPorts) > 0 {
		device.Metadata["lastReachablePorts"] = strings.Join(openPorts, ",")
	}
	if panelLink, source, ok := derivePanelLink(device.Metadata, coalesce(strings.TrimSpace(device.Hostname), targetIP), openPorts); ok {
		device.Metadata["panelLink"] = panelLink
		device.Metadata["panelLinkSource"] = source
	}

	switch {
	case pingOK || tcpOpen:
		device.Status = "online"
	case tcpRefused || hasARP:
		device.Status = "degraded"
	default:
		device.Status = "offline"
	}

	return device, persistIfChanged(ctx, r.store, original, device), device.Status, macResolved, nil
}

func (r *Refresher) refreshNetworkNode(ctx context.Context, node store.NetworkNode) (store.NetworkNode, bool, string, bool, error) {
	if r.nmapPath != "" {
		return r.refreshNetworkNodeWithNmap(ctx, node)
	}
	return r.refreshNetworkNodeFallback(ctx, node)
}

func (r *Refresher) refreshNetworkNodeWithNmap(ctx context.Context, node store.NetworkNode) (store.NetworkNode, bool, string, bool, error) {
	original := node
	targetIP := strings.TrimSpace(node.ManagementIP)
	if targetIP == "" {
		node.Status = "unknown"
		return node, persistNodeIfChanged(ctx, r.store, original, node), "unknown", false, nil
	}

	nm := nmapScanOne(ctx, r.nmapPath, targetIP, candidatePortsForNode(node))
	node = applyNmapToNode(node, nm)

	macResolved := nm.MAC != "" && nm.MAC != original.MACAddress
	updated := persistNodeIfChanged(ctx, r.store, original, node)
	return node, updated, node.Status, macResolved, nil
}

func (r *Refresher) refreshNetworkNodeFallback(ctx context.Context, node store.NetworkNode) (store.NetworkNode, bool, string, bool, error) {
	original := node
	targetIP := strings.TrimSpace(node.ManagementIP)
	macResolved := false
	if node.Metadata == nil {
		node.Metadata = map[string]string{}
	}

	if targetIP == "" {
		node.Status = "unknown"
		return node, persistNodeIfChanged(ctx, r.store, original, node), "unknown", false, nil
	}

	pingOK := pingHost(targetIP, 1500*time.Millisecond)
	tcpOpen := false
	tcpRefused := false
	var openPorts []string
	if !pingOK {
		tcpOpen, tcpRefused, openPorts = probeTCPPorts(targetIP, candidatePortsForNode(node))
	}
	openPorts = mergeOpenPorts(openPorts, probeSelectedPorts(targetIP, 443, 80))
	hasARP := false

	if pingOK || tcpOpen {
		if macAddress, err := lookupMAC(targetIP); err == nil && macAddress != "" {
			hasARP = true
			if macAddress != node.MACAddress {
				node.MACAddress = macAddress
				macResolved = true
			}
		}
	} else if macAddress, err := lookupMAC(targetIP); err == nil && macAddress != "" {
		hasARP = true
		if node.MACAddress == "" {
			node.MACAddress = macAddress
			macResolved = true
		}
	}

	if len(openPorts) > 0 {
		node.Metadata["lastReachablePorts"] = strings.Join(openPorts, ",")
	}
	if panelLink, source, ok := derivePanelLink(node.Metadata, targetIP, openPorts); ok {
		node.Metadata["panelLink"] = panelLink
		node.Metadata["panelLinkSource"] = source
	}

	switch {
	case pingOK || tcpOpen:
		node.Status = "online"
	case tcpRefused || hasARP:
		node.Status = "degraded"
	default:
		node.Status = "offline"
	}

	return node, persistNodeIfChanged(ctx, r.store, original, node), node.Status, macResolved, nil
}

func persistIfChanged(ctx context.Context, inventory *store.Store, original store.Device, current store.Device) bool {
	persisted := current
	persisted.Status = original.Status
	if devicesEqualIgnoringStatus(original, persisted) {
		return false
	}

	_, err := inventory.UpdateDevice(ctx, persisted)
	return err == nil
}

func persistNodeIfChanged(ctx context.Context, inventory *store.Store, original store.NetworkNode, current store.NetworkNode) bool {
	persisted := current
	persisted.Status = original.Status
	if networkNodesEqualIgnoringStatus(original, persisted) {
		return false
	}

	_, err := inventory.UpdateNetworkNode(ctx, persisted)
	return err == nil
}

func devicesEqualIgnoringStatus(left store.Device, right store.Device) bool {
	if left.Name != right.Name ||
		left.Hostname != right.Hostname ||
		left.Role != right.Role ||
		left.DeviceType != right.DeviceType ||
		left.IPAddress != right.IPAddress ||
		left.MACAddress != right.MACAddress ||
		left.NetworkSegment != right.NetworkSegment ||
		strings.Join(left.Tags, ",") != strings.Join(right.Tags, ",") {
		return false
	}

	if len(left.Metadata) != len(right.Metadata) {
		return false
	}
	for key, value := range left.Metadata {
		if right.Metadata[key] != value {
			return false
		}
	}

	return true
}

func networkNodesEqualIgnoringStatus(left store.NetworkNode, right store.NetworkNode) bool {
	if left.Name != right.Name ||
		left.NodeType != right.NodeType ||
		left.ManagementIP != right.ManagementIP ||
		left.MACAddress != right.MACAddress ||
		left.Vendor != right.Vendor ||
		left.Model != right.Model ||
		strings.Join(left.Tags, ",") != strings.Join(right.Tags, ",") {
		return false
	}

	if len(left.Metadata) != len(right.Metadata) {
		return false
	}
	for key, value := range left.Metadata {
		if right.Metadata[key] != value {
			return false
		}
	}

	return true
}

func resolveIPv4(hostname string) (string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", fmt.Errorf("no ipv4 found")
}

func reverseLookup(ipAddress string) (string, error) {
	names, err := net.LookupAddr(ipAddress)
	if err != nil || len(names) == 0 {
		return "", fmt.Errorf("reverse lookup failed")
	}

	return strings.TrimSuffix(names[0], "."), nil
}

func pingHost(target string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()

	var command *exec.Cmd
	if runtime.GOOS == "windows" {
		command = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.Itoa(int(timeout.Milliseconds())), target)
	} else {
		seconds := int(timeout.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		command = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(seconds), target)
	}

	return command.Run() == nil
}

func lookupMAC(ipAddress string) (string, error) {
	if runtime.GOOS == "windows" {
		output, err := exec.Command("arp", "-a", ipAddress).CombinedOutput()
		if err != nil {
			return "", err
		}

		match := macAddressDashRegex.FindString(string(output))
		if match == "" {
			return "", fmt.Errorf("no mac address found")
		}

		return strings.ToUpper(strings.ReplaceAll(match, "-", ":")), nil
	}

	output, err := exec.Command("arp", "-n", ipAddress).CombinedOutput()
	if err != nil {
		return "", err
	}

	match := macAddressColonRegex.FindString(string(output))
	if match == "" {
		return "", fmt.Errorf("no mac address found")
	}

	return strings.ToUpper(match), nil
}

func candidatePorts(device store.Device) []int {
	seen := map[int]bool{}
	var ports []int

	add := func(values ...int) {
		for _, value := range values {
			if value <= 0 || seen[value] {
				continue
			}
			seen[value] = true
			ports = append(ports, value)
		}
	}

	add(443, 80, 22, 445)

	deviceType := strings.ToLower(device.DeviceType)
	role := strings.ToLower(device.Role)

	if strings.Contains(deviceType, "nas") || strings.Contains(role, "storage") {
		add(5000, 5001, 2049)
	}
	if strings.Contains(deviceType, "router") || strings.Contains(deviceType, "switch") || strings.Contains(deviceType, "access-point") || strings.Contains(deviceType, "ap") {
		add(53, 161)
	}
	if strings.Contains(deviceType, "windows") || strings.Contains(role, "workstation") {
		add(139, 5985, 5986)
	}
	if strings.Contains(deviceType, "linux") || strings.Contains(deviceType, "raspberry") || strings.Contains(role, "controller") {
		add(22)
	}

	return ports
}

func candidatePortsForNode(node store.NetworkNode) []int {
	seen := map[int]bool{}
	var ports []int

	add := func(values ...int) {
		for _, value := range values {
			if value <= 0 || seen[value] {
				continue
			}
			seen[value] = true
			ports = append(ports, value)
		}
	}

	add(443, 80, 22, 53, 161)

	nodeType := strings.ToLower(node.NodeType)
	if strings.Contains(nodeType, "switch") {
		add(22, 80, 443, 161)
	}
	if strings.Contains(nodeType, "router") || strings.Contains(nodeType, "gateway") {
		add(22, 80, 443, 53, 161)
	}
	if strings.Contains(nodeType, "access-point") || strings.Contains(nodeType, "ap") {
		add(22, 80, 443, 161)
	}

	return ports
}

func probeTCPPorts(ipAddress string, ports []int) (bool, bool, []string) {
	for _, port := range ports {
		address := net.JoinHostPort(ipAddress, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, 750*time.Millisecond)
		if err == nil {
			openPort := strconv.Itoa(port)
			_ = conn.Close()
			return true, false, []string{openPort}
		}

		errText := strings.ToLower(err.Error())
		if strings.Contains(errText, "connection refused") {
			return false, true, nil
		}
	}

	return false, false, nil
}

func probeSelectedPorts(ipAddress string, ports ...int) []string {
	var openPorts []string
	for _, port := range ports {
		address := net.JoinHostPort(ipAddress, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			openPorts = append(openPorts, strconv.Itoa(port))
		}
	}

	return openPorts
}

func mergeOpenPorts(base []string, extras []string) []string {
	if len(extras) == 0 {
		return base
	}

	seen := make(map[string]bool, len(base)+len(extras))
	merged := make([]string, 0, len(base)+len(extras))
	for _, value := range base {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		merged = append(merged, value)
	}
	for _, value := range extras {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		merged = append(merged, value)
	}

	return merged
}

func derivePanelLink(metadata map[string]string, host string, openPorts []string) (string, string, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", false
	}

	existing := strings.TrimSpace(metadata["panelLink"])
	source := strings.TrimSpace(metadata["panelLinkSource"])
	if existing != "" && source != "auto" {
		return "", "", false
	}

	has443 := false
	has80 := false
	for _, port := range openPorts {
		switch strings.TrimSpace(port) {
		case "443":
			has443 = true
		case "80":
			has80 = true
		}
	}

	switch {
	case has443:
		return "https://" + host, "auto", true
	case has80:
		return "http://" + host, "auto", true
	case existing != "" && source == "auto":
		return "", "", true
	default:
		return "", "", false
	}
}

func coalesce(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}

	return ""
}
