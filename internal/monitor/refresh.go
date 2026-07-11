package monitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
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

const (
	refreshConcurrency = 8
	batchScanTimeout   = 30 * time.Second
	singleScanTimeout  = 10 * time.Second
	targetProbeTimeout = 10 * time.Second
	dnsLookupTimeout   = 2 * time.Second
	maxBatchScanPorts  = 64
)

type RefreshSummary struct {
	Checked     int  `json:"checked"`
	Updated     int  `json:"updated"`
	Skipped     int  `json:"skipped"`
	Online      int  `json:"online"`
	Degraded    int  `json:"degraded"`
	Offline     int  `json:"offline"`
	Unknown     int  `json:"unknown"`
	MACResolved int  `json:"macResolved"`
	Partial     bool `json:"partial"`
}

type RefreshResult struct {
	Summary      RefreshSummary      `json:"summary"`
	Devices      []store.Device      `json:"devices"`
	NetworkNodes []store.NetworkNode `json:"networkNodes"`
	NmapUsed     bool                `json:"nmapUsed"`
}

type RefresherOptions struct {
	NmapPath string
}

type nmapScanFunc func(context.Context, string, []string, []int) (map[string]nmapScanResult, error)

type probeSet struct {
	resolveIPv4   func(context.Context, string) (string, error)
	reverseLookup func(context.Context, string) (string, error)
	pingHost      func(context.Context, string, time.Duration) (bool, error)
	lookupMAC     func(context.Context, string) (string, error)
	probeTCPPorts func(context.Context, string, []int) (bool, bool, []string, error)
}

type Refresher struct {
	store    *store.Store
	bus      *EventBus
	nmapPath string
	scanGate chan struct{}
	nmapScan nmapScanFunc
	probes   probeSet
}

type nmapExecutionError struct {
	err error
}

func (e *nmapExecutionError) Error() string { return e.err.Error() }
func (e *nmapExecutionError) Unwrap() error { return e.err }

func NewRefresher(inventory *store.Store, bus *EventBus) *Refresher {
	return NewRefresherWithOptions(inventory, bus, RefresherOptions{NmapPath: nmapDetect()})
}

func NewRefresherWithOptions(inventory *store.Store, bus *EventBus, options RefresherOptions) *Refresher {
	path := ""
	if configured := strings.TrimSpace(options.NmapPath); configured != "" {
		if resolved, err := exec.LookPath(configured); err == nil {
			path = resolved
		}
	}
	if bus == nil {
		bus = NewEventBus()
	}

	return &Refresher{
		store:    inventory,
		bus:      bus,
		nmapPath: path,
		scanGate: make(chan struct{}, 1),
		nmapScan: nmapScan,
		probes: probeSet{
			resolveIPv4:   resolveIPv4,
			reverseLookup: reverseLookup,
			pingHost:      pingHost,
			lookupMAC:     lookupMAC,
			probeTCPPorts: probeTCPPorts,
		},
	}
}

func (r *Refresher) UsingNmap() bool { return r.nmapPath != "" }

func (r *Refresher) RunBackground(ctx context.Context, interval time.Duration) {
	log.Printf("background refresh loop started: interval=%s nmap_enabled=%t", interval, r.UsingNmap())
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
	release, err := r.acquireScan(ctx)
	if err != nil {
		return
	}
	defer release()

	devices, nodes, err := r.loadInventory(ctx)
	if err != nil {
		log.Printf("background refresh: load inventory failed: %v", err)
		return
	}

	deviceIDs := make([]string, len(devices))
	for index, device := range devices {
		deviceIDs[index] = device.ID
	}
	nodeIDs := make([]string, len(nodes))
	for index, node := range nodes {
		nodeIDs[index] = node.ID
	}
	r.bus.publishJSON(EventScanStarted, map[string]any{"deviceIds": deviceIDs, "nodeIds": nodeIDs})

	result, err := r.refreshInventory(ctx, devices, nodes)
	if err != nil {
		log.Printf("background refresh failed: %v", err)
		r.bus.publishJSON(EventScanComplete, map[string]any{
			"checked": 0, "updated": 0, "online": 0, "degraded": 0,
			"offline": 0, "unknown": len(devices) + len(nodes), "skipped": 0, "partial": false, "nmapUsed": false,
			"error": "refresh failed",
		})
		return
	}

	for _, device := range result.Devices {
		r.bus.publishJSON(EventDeviceUpdate, device)
	}
	for _, node := range result.NetworkNodes {
		r.bus.publishJSON(EventNodeUpdate, node)
	}
	r.bus.publishJSON(EventScanComplete, map[string]any{
		"checked": result.Summary.Checked, "updated": result.Summary.Updated,
		"skipped": result.Summary.Skipped, "partial": result.Summary.Partial,
		"online": result.Summary.Online, "degraded": result.Summary.Degraded,
		"offline": result.Summary.Offline, "unknown": result.Summary.Unknown,
		"nmapUsed": result.NmapUsed,
	})
	log.Printf(
		"background refresh completed: checked=%d updated=%d skipped=%d online=%d degraded=%d offline=%d unknown=%d nmap_used=%t",
		result.Summary.Checked, result.Summary.Updated, result.Summary.Skipped, result.Summary.Online,
		result.Summary.Degraded, result.Summary.Offline, result.Summary.Unknown, result.NmapUsed,
	)
}

func (r *Refresher) acquireScan(ctx context.Context) (func(), error) {
	select {
	case r.scanGate <- struct{}{}:
		return func() { <-r.scanGate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *Refresher) loadInventory(ctx context.Context) ([]store.Device, []store.NetworkNode, error) {
	devices, err := r.store.ListDevices(ctx)
	if err != nil {
		return nil, nil, err
	}
	nodes, err := r.store.ListNetworkNodes(ctx)
	if err != nil {
		return nil, nil, err
	}
	return devices, nodes, nil
}

func (r *Refresher) RefreshAll(ctx context.Context) (RefreshResult, error) {
	release, err := r.acquireScan(ctx)
	if err != nil {
		return RefreshResult{}, err
	}
	defer release()

	devices, nodes, err := r.loadInventory(ctx)
	if err != nil {
		return RefreshResult{}, err
	}
	return r.refreshInventory(ctx, devices, nodes)
}

func (r *Refresher) refreshInventory(ctx context.Context, devices []store.Device, nodes []store.NetworkNode) (RefreshResult, error) {
	if r.UsingNmap() {
		result, err := r.batchScanWithNmap(ctx, devices, nodes)
		if err == nil {
			return result, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return RefreshResult{}, ctxErr
		}
		var executionError *nmapExecutionError
		if !errors.As(err, &executionError) {
			return RefreshResult{}, err
		}
		log.Printf("nmap batch scan failed; using bounded fallback probes: %v", executionError)
	}
	return r.refreshAllFallback(ctx, devices, nodes)
}

func (r *Refresher) batchScanWithNmap(ctx context.Context, devices []store.Device, nodes []store.NetworkNode) (RefreshResult, error) {
	refreshedDevices := cloneDevices(devices)
	refreshedNodes := cloneNetworkNodes(nodes)
	type target struct {
		ip       string
		isDevice bool
		index    int
	}
	targets := make([]target, 0, len(devices)+len(nodes))
	ips := make([]string, 0, len(devices)+len(nodes))
	seenIPs := make(map[string]struct{}, len(devices)+len(nodes))
	targetDevices := make([]store.Device, 0, len(devices))
	targetNodes := make([]store.NetworkNode, 0, len(nodes))

	for index := range refreshedDevices {
		refreshedDevices[index].Status = "unknown"
		ip, ok, err := r.canonicalDeviceTarget(ctx, &refreshedDevices[index])
		if err != nil {
			return RefreshResult{}, err
		}
		if !ok {
			continue
		}
		targets = append(targets, target{ip: ip, isDevice: true, index: index})
		targetDevices = append(targetDevices, refreshedDevices[index])
		if _, exists := seenIPs[ip]; !exists {
			seenIPs[ip] = struct{}{}
			ips = append(ips, ip)
		}
	}
	for index := range refreshedNodes {
		refreshedNodes[index].Status = "unknown"
		ip, ok := canonicalNodeTarget(&refreshedNodes[index])
		if !ok {
			continue
		}
		targets = append(targets, target{ip: ip, index: index})
		targetNodes = append(targetNodes, refreshedNodes[index])
		if _, exists := seenIPs[ip]; !exists {
			seenIPs[ip] = struct{}{}
			ips = append(ips, ip)
		}
	}

	nmapResults := map[string]nmapScanResult{}
	nmapUsed := len(ips) > 0
	if nmapUsed {
		scanCtx, cancel := context.WithTimeout(ctx, batchScanTimeout)
		results, err := r.nmapScan(scanCtx, r.nmapPath, ips, batchCandidatePorts(targetDevices, targetNodes))
		cancel()
		if err != nil {
			return RefreshResult{}, &nmapExecutionError{err: err}
		}
		nmapResults = results
	}

	for _, current := range targets {
		result := nmapResults[current.ip]
		result.IP = current.ip
		if current.isDevice {
			refreshedDevices[current.index] = applyNmapToDevice(refreshedDevices[current.index], result)
		} else {
			refreshedNodes[current.index] = applyNmapToNode(refreshedNodes[current.index], result)
		}
	}

	summary := RefreshSummary{Checked: len(devices) + len(nodes)}
	resultDevices := make([]store.Device, 0, len(refreshedDevices))
	for index := range refreshedDevices {
		observedMAC := refreshedDevices[index].MACAddress
		macResolved := refreshedDevices[index].MACAddress != "" && refreshedDevices[index].MACAddress != devices[index].MACAddress
		updated, err := persistIfChanged(ctx, r.store, devices[index], &refreshedDevices[index])
		if err != nil {
			if !isSkippableRefreshError(err) {
				return RefreshResult{}, err
			}
			summary.Skipped++
			summary.Partial = true
			if errors.Is(err, store.ErrConflict) {
				resultDevices = append(resultDevices, refreshedDevices[index])
			}
			continue
		}
		resultDevices = append(resultDevices, refreshedDevices[index])
		if updated {
			summary.Updated++
		}
		if macResolved && updated && refreshedDevices[index].MACAddress == observedMAC {
			summary.MACResolved++
		}
		accumulateStatus(&summary, refreshedDevices[index].Status)
	}
	resultNodes := make([]store.NetworkNode, 0, len(refreshedNodes))
	for index := range refreshedNodes {
		observedMAC := refreshedNodes[index].MACAddress
		macResolved := refreshedNodes[index].MACAddress != "" && refreshedNodes[index].MACAddress != nodes[index].MACAddress
		updated, err := persistNodeIfChanged(ctx, r.store, nodes[index], &refreshedNodes[index])
		if err != nil {
			if !isSkippableRefreshError(err) {
				return RefreshResult{}, err
			}
			summary.Skipped++
			summary.Partial = true
			if errors.Is(err, store.ErrConflict) {
				resultNodes = append(resultNodes, refreshedNodes[index])
			}
			continue
		}
		resultNodes = append(resultNodes, refreshedNodes[index])
		if updated {
			summary.Updated++
		}
		if macResolved && updated && refreshedNodes[index].MACAddress == observedMAC {
			summary.MACResolved++
		}
		accumulateStatus(&summary, refreshedNodes[index].Status)
	}

	return RefreshResult{
		Summary: summary, Devices: resultDevices, NetworkNodes: resultNodes, NmapUsed: nmapUsed,
	}, nil
}

func applyNmapToDevice(device store.Device, result nmapScanResult) store.Device {
	device = cloneDevice(device)
	if result.MAC != "" {
		device.MACAddress = result.MAC
	}
	if hostname, ok := canonicalObservedHostname(result.Hostname); ok && strings.TrimSpace(device.Hostname) == "" {
		device.Hostname = hostname
	}
	setReachabilityMetadata(device.Metadata, coalesce(device.Hostname, device.IPAddress), result.OpenPorts)

	switch {
	case result.Up || len(result.OpenPorts) > 0:
		device.Status = "online"
	case result.MAC != "":
		device.Status = "degraded"
	default:
		device.Status = "offline"
	}
	return device
}

func applyNmapToNode(node store.NetworkNode, result nmapScanResult) store.NetworkNode {
	node = cloneNetworkNode(node)
	if result.MAC != "" {
		node.MACAddress = result.MAC
	}
	setReachabilityMetadata(node.Metadata, node.ManagementIP, result.OpenPorts)

	switch {
	case result.Up || len(result.OpenPorts) > 0:
		node.Status = "online"
	case result.MAC != "":
		node.Status = "degraded"
	default:
		node.Status = "offline"
	}
	return node
}

func (r *Refresher) refreshAllFallback(ctx context.Context, devices []store.Device, nodes []store.NetworkNode) (RefreshResult, error) {
	refreshedDevices, deviceSummary, err := r.refreshDevicesParallel(ctx, devices, r.refreshDeviceFallback)
	if err != nil {
		return RefreshResult{}, err
	}
	refreshedNodes, nodeSummary, err := r.refreshNodesParallel(ctx, nodes, r.refreshNetworkNodeFallback)
	if err != nil {
		return RefreshResult{}, err
	}
	return RefreshResult{
		Summary:      mergeSummaries(deviceSummary, nodeSummary),
		Devices:      refreshedDevices,
		NetworkNodes: refreshedNodes,
	}, nil
}

type deviceRefreshFunc func(context.Context, store.Device) (store.Device, bool, string, bool, error)

func (r *Refresher) refreshDevicesParallel(ctx context.Context, devices []store.Device, refresh deviceRefreshFunc) ([]store.Device, RefreshSummary, error) {
	type result struct {
		device      store.Device
		updated     bool
		status      string
		macResolved bool
		skipped     bool
		include     bool
	}
	results := make([]result, len(devices))
	if len(devices) == 0 {
		return []store.Device{}, RefreshSummary{}, nil
	}

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var next int
	var workMu sync.Mutex
	var firstErr error
	workers := min(len(devices), refreshConcurrency)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for {
				workMu.Lock()
				if firstErr != nil || next >= len(devices) {
					workMu.Unlock()
					return
				}
				index := next
				next++
				workMu.Unlock()

				device, updated, status, macResolved, err := refresh(workCtx, cloneDevice(devices[index]))
				if err != nil {
					if isSkippableRefreshError(err) {
						results[index] = result{
							device: device, skipped: true, include: errors.Is(err, store.ErrConflict),
						}
						continue
					}
					workMu.Lock()
					if firstErr == nil {
						firstErr = err
						cancel()
					}
					workMu.Unlock()
					return
				}
				results[index] = result{device: device, updated: updated, status: status, macResolved: macResolved, include: true}
			}
		}()
	}
	group.Wait()
	if firstErr != nil {
		return nil, RefreshSummary{}, firstErr
	}

	refreshed := make([]store.Device, 0, len(results))
	summary := RefreshSummary{Checked: len(results)}
	for _, current := range results {
		if current.include {
			refreshed = append(refreshed, current.device)
		}
		if current.skipped {
			summary.Skipped++
			summary.Partial = true
			continue
		}
		if current.updated {
			summary.Updated++
		}
		if current.macResolved {
			summary.MACResolved++
		}
		accumulateStatus(&summary, current.status)
	}
	return refreshed, summary, nil
}

type nodeRefreshFunc func(context.Context, store.NetworkNode) (store.NetworkNode, bool, string, bool, error)

func (r *Refresher) refreshNodesParallel(ctx context.Context, nodes []store.NetworkNode, refresh nodeRefreshFunc) ([]store.NetworkNode, RefreshSummary, error) {
	type result struct {
		node        store.NetworkNode
		updated     bool
		status      string
		macResolved bool
		skipped     bool
		include     bool
	}
	results := make([]result, len(nodes))
	if len(nodes) == 0 {
		return []store.NetworkNode{}, RefreshSummary{}, nil
	}

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var next int
	var workMu sync.Mutex
	var firstErr error
	workers := min(len(nodes), refreshConcurrency)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for {
				workMu.Lock()
				if firstErr != nil || next >= len(nodes) {
					workMu.Unlock()
					return
				}
				index := next
				next++
				workMu.Unlock()

				node, updated, status, macResolved, err := refresh(workCtx, cloneNetworkNode(nodes[index]))
				if err != nil {
					if isSkippableRefreshError(err) {
						results[index] = result{
							node: node, skipped: true, include: errors.Is(err, store.ErrConflict),
						}
						continue
					}
					workMu.Lock()
					if firstErr == nil {
						firstErr = err
						cancel()
					}
					workMu.Unlock()
					return
				}
				results[index] = result{node: node, updated: updated, status: status, macResolved: macResolved, include: true}
			}
		}()
	}
	group.Wait()
	if firstErr != nil {
		return nil, RefreshSummary{}, firstErr
	}

	refreshed := make([]store.NetworkNode, 0, len(results))
	summary := RefreshSummary{Checked: len(results)}
	for _, current := range results {
		if current.include {
			refreshed = append(refreshed, current.node)
		}
		if current.skipped {
			summary.Skipped++
			summary.Partial = true
			continue
		}
		if current.updated {
			summary.Updated++
		}
		if current.macResolved {
			summary.MACResolved++
		}
		accumulateStatus(&summary, current.status)
	}
	return refreshed, summary, nil
}

func (r *Refresher) RefreshDeviceByID(ctx context.Context, id string) error {
	release, err := r.acquireScan(ctx)
	if err != nil {
		return err
	}
	defer release()

	device, err := r.store.GetDevice(ctx, id)
	if err != nil {
		return err
	}
	_, _, _, _, err = r.refreshDevice(ctx, device)
	return err
}

func (r *Refresher) RefreshDeviceSnapshotByID(ctx context.Context, id string) (store.Device, error) {
	release, err := r.acquireScan(ctx)
	if err != nil {
		return store.Device{}, err
	}
	defer release()

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
	release, err := r.acquireScan(ctx)
	if err != nil {
		return store.NetworkNode{}, err
	}
	defer release()

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
	if r.UsingNmap() {
		refreshed, updated, status, macResolved, err := r.refreshDeviceWithNmap(ctx, device)
		if err == nil {
			return refreshed, updated, status, macResolved, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return store.Device{}, false, "unknown", false, ctxErr
		}
		var executionError *nmapExecutionError
		if !errors.As(err, &executionError) {
			return store.Device{}, false, "unknown", false, err
		}
	}
	return r.refreshDeviceFallback(ctx, device)
}

func (r *Refresher) refreshDeviceWithNmap(ctx context.Context, device store.Device) (store.Device, bool, string, bool, error) {
	original := cloneDevice(device)
	device = cloneDevice(device)
	targetIP, ok, err := r.canonicalDeviceTarget(ctx, &device)
	if err != nil {
		return store.Device{}, false, "unknown", false, err
	}
	if !ok {
		device.Status = "unknown"
		updated, err := persistIfChanged(ctx, r.store, original, &device)
		return device, updated, device.Status, false, err
	}

	scanCtx, cancel := context.WithTimeout(ctx, singleScanTimeout)
	result, err := nmapScanOne(scanCtx, r.nmapScan, r.nmapPath, targetIP, candidatePorts(device))
	cancel()
	if err != nil {
		return store.Device{}, false, "unknown", false, &nmapExecutionError{err: err}
	}
	device = applyNmapToDevice(device, result)
	observedMAC := device.MACAddress
	macResolved := device.MACAddress != "" && device.MACAddress != original.MACAddress
	updated, err := persistIfChanged(ctx, r.store, original, &device)
	macResolved = macResolved && updated && device.MACAddress == observedMAC
	return device, updated, device.Status, macResolved, err
}

func (r *Refresher) refreshDeviceFallback(ctx context.Context, device store.Device) (store.Device, bool, string, bool, error) {
	original := cloneDevice(device)
	device = cloneDevice(device)
	targetIP, ok, err := r.canonicalDeviceTarget(ctx, &device)
	if err != nil {
		return store.Device{}, false, "unknown", false, err
	}
	if !ok {
		device.Status = "unknown"
		updated, err := persistIfChanged(ctx, r.store, original, &device)
		return device, updated, device.Status, false, err
	}

	probeCtx, cancel := context.WithTimeout(ctx, targetProbeTimeout)
	defer cancel()
	pingOK, _ := r.probes.pingHost(probeCtx, targetIP, 1500*time.Millisecond)
	ports := candidatePorts(device)
	if pingOK {
		ports = []int{443, 80}
		if sshPort, ok := configuredSSHPort(device); ok && sshPort != 443 && sshPort != 80 {
			ports = append(ports, sshPort)
		}
	}
	tcpOpen, tcpRefused, openPorts, tcpErr := r.probes.probeTCPPorts(probeCtx, targetIP, ports)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return store.Device{}, false, "unknown", false, ctxErr
	}
	probeTimedOut := errors.Is(probeCtx.Err(), context.DeadlineExceeded) || errors.Is(tcpErr, context.DeadlineExceeded)
	if tcpErr != nil && !probeTimedOut {
		return store.Device{}, false, "unknown", false, tcpErr
	}
	if probeTimedOut && !pingOK && !tcpOpen && !tcpRefused {
		unknown := cloneDevice(original)
		unknown.Status = "unknown"
		updated, persistErr := persistIfChanged(ctx, r.store, original, &unknown)
		return unknown, updated, unknown.Status, false, persistErr
	}

	hasARP := false
	if !probeTimedOut {
		if macAddress, lookupErr := r.probes.lookupMAC(probeCtx, targetIP); lookupErr == nil && macAddress != "" {
			hasARP = true
			device.MACAddress = macAddress
		}
		if (pingOK || tcpOpen) && strings.TrimSpace(device.Hostname) == "" {
			if hostname, lookupErr := r.probes.reverseLookup(probeCtx, targetIP); lookupErr == nil {
				if canonical, ok := canonicalObservedHostname(hostname); ok {
					device.Hostname = canonical
				}
			}
		}
	}
	setReachabilityMetadata(device.Metadata, coalesce(device.Hostname, targetIP), parsePorts(openPorts))

	switch {
	case pingOK || tcpOpen:
		device.Status = "online"
	case tcpRefused || hasARP:
		device.Status = "degraded"
	default:
		device.Status = "offline"
	}
	observedMAC := device.MACAddress
	macResolved := device.MACAddress != "" && device.MACAddress != original.MACAddress
	updated, err := persistIfChanged(ctx, r.store, original, &device)
	macResolved = macResolved && updated && device.MACAddress == observedMAC
	return device, updated, device.Status, macResolved, err
}

func (r *Refresher) refreshNetworkNode(ctx context.Context, node store.NetworkNode) (store.NetworkNode, bool, string, bool, error) {
	if r.UsingNmap() {
		refreshed, updated, status, macResolved, err := r.refreshNetworkNodeWithNmap(ctx, node)
		if err == nil {
			return refreshed, updated, status, macResolved, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return store.NetworkNode{}, false, "unknown", false, ctxErr
		}
		var executionError *nmapExecutionError
		if !errors.As(err, &executionError) {
			return store.NetworkNode{}, false, "unknown", false, err
		}
	}
	return r.refreshNetworkNodeFallback(ctx, node)
}

func (r *Refresher) refreshNetworkNodeWithNmap(ctx context.Context, node store.NetworkNode) (store.NetworkNode, bool, string, bool, error) {
	original := cloneNetworkNode(node)
	node = cloneNetworkNode(node)
	targetIP, ok := canonicalNodeTarget(&node)
	if !ok {
		node.Status = "unknown"
		updated, err := persistNodeIfChanged(ctx, r.store, original, &node)
		return node, updated, node.Status, false, err
	}

	scanCtx, cancel := context.WithTimeout(ctx, singleScanTimeout)
	result, err := nmapScanOne(scanCtx, r.nmapScan, r.nmapPath, targetIP, candidatePortsForNode(node))
	cancel()
	if err != nil {
		return store.NetworkNode{}, false, "unknown", false, &nmapExecutionError{err: err}
	}
	node = applyNmapToNode(node, result)
	observedMAC := node.MACAddress
	macResolved := node.MACAddress != "" && node.MACAddress != original.MACAddress
	updated, err := persistNodeIfChanged(ctx, r.store, original, &node)
	macResolved = macResolved && updated && node.MACAddress == observedMAC
	return node, updated, node.Status, macResolved, err
}

func (r *Refresher) refreshNetworkNodeFallback(ctx context.Context, node store.NetworkNode) (store.NetworkNode, bool, string, bool, error) {
	original := cloneNetworkNode(node)
	node = cloneNetworkNode(node)
	targetIP, ok := canonicalNodeTarget(&node)
	if !ok {
		node.Status = "unknown"
		updated, err := persistNodeIfChanged(ctx, r.store, original, &node)
		return node, updated, node.Status, false, err
	}

	probeCtx, cancel := context.WithTimeout(ctx, targetProbeTimeout)
	defer cancel()
	pingOK, _ := r.probes.pingHost(probeCtx, targetIP, 1500*time.Millisecond)
	ports := candidatePortsForNode(node)
	if pingOK {
		ports = []int{443, 80}
	}
	tcpOpen, tcpRefused, openPorts, tcpErr := r.probes.probeTCPPorts(probeCtx, targetIP, ports)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return store.NetworkNode{}, false, "unknown", false, ctxErr
	}
	probeTimedOut := errors.Is(probeCtx.Err(), context.DeadlineExceeded) || errors.Is(tcpErr, context.DeadlineExceeded)
	if tcpErr != nil && !probeTimedOut {
		return store.NetworkNode{}, false, "unknown", false, tcpErr
	}
	if probeTimedOut && !pingOK && !tcpOpen && !tcpRefused {
		unknown := cloneNetworkNode(original)
		unknown.Status = "unknown"
		updated, persistErr := persistNodeIfChanged(ctx, r.store, original, &unknown)
		return unknown, updated, unknown.Status, false, persistErr
	}

	hasARP := false
	if !probeTimedOut {
		if macAddress, lookupErr := r.probes.lookupMAC(probeCtx, targetIP); lookupErr == nil && macAddress != "" {
			hasARP = true
			node.MACAddress = macAddress
		}
	}
	setReachabilityMetadata(node.Metadata, targetIP, parsePorts(openPorts))

	switch {
	case pingOK || tcpOpen:
		node.Status = "online"
	case tcpRefused || hasARP:
		node.Status = "degraded"
	default:
		node.Status = "offline"
	}
	observedMAC := node.MACAddress
	macResolved := node.MACAddress != "" && node.MACAddress != original.MACAddress
	updated, err := persistNodeIfChanged(ctx, r.store, original, &node)
	macResolved = macResolved && updated && node.MACAddress == observedMAC
	return node, updated, node.Status, macResolved, err
}

func (r *Refresher) canonicalDeviceTarget(ctx context.Context, device *store.Device) (string, bool, error) {
	if candidate := strings.TrimSpace(device.IPAddress); candidate != "" {
		canonical, err := canonicalIPv4(candidate)
		if err != nil {
			return "", false, nil
		}
		device.IPAddress = canonical
		return canonical, true, nil
	}

	hostname := strings.TrimSpace(device.Hostname)
	if hostname == "" {
		return "", false, nil
	}
	resolved, err := r.probes.resolveIPv4(ctx, hostname)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", false, ctxErr
		}
		return "", false, nil
	}
	canonical, err := canonicalIPv4(resolved)
	if err != nil {
		return "", false, nil
	}
	return canonical, true, nil
}

func canonicalNodeTarget(node *store.NetworkNode) (string, bool) {
	canonical, err := canonicalIPv4(node.ManagementIP)
	if err != nil {
		return "", false
	}
	node.ManagementIP = canonical
	return canonical, true
}

func persistIfChanged(ctx context.Context, inventory *store.Store, original store.Device, current *store.Device) (bool, error) {
	persisted := cloneDevice(*current)
	if devicesEqual(original, persisted) {
		latest, err := inventory.GetDevice(ctx, original.ID)
		if err != nil {
			return false, err
		}
		*current = cloneDevice(latest)
		return false, nil
	}

	updated, err := inventory.UpdateDevice(ctx, persisted)
	if err == nil {
		*current = cloneDevice(updated)
		return true, nil
	}
	if !errors.Is(err, store.ErrConflict) {
		return false, err
	}

	latest, err := inventory.GetDevice(ctx, original.ID)
	if err != nil {
		return false, err
	}
	if latest.IPAddress != original.IPAddress || latest.Hostname != original.Hostname {
		*current = cloneDevice(latest)
		return false, nil
	}
	merged := mergeObservedDevice(original, persisted, latest)
	if devicesEqual(latest, merged) {
		*current = cloneDevice(latest)
		return false, nil
	}
	updated, err = inventory.UpdateDevice(ctx, merged)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			latest, latestErr := inventory.GetDevice(ctx, original.ID)
			if latestErr != nil {
				return false, latestErr
			}
			*current = cloneDevice(latest)
		}
		return false, err
	}
	*current = cloneDevice(updated)
	return true, nil
}

func persistNodeIfChanged(ctx context.Context, inventory *store.Store, original store.NetworkNode, current *store.NetworkNode) (bool, error) {
	persisted := cloneNetworkNode(*current)
	if networkNodesEqual(original, persisted) {
		latest, err := inventory.GetNetworkNode(ctx, original.ID)
		if err != nil {
			return false, err
		}
		*current = cloneNetworkNode(latest)
		return false, nil
	}

	updated, err := inventory.UpdateNetworkNode(ctx, persisted)
	if err == nil {
		*current = cloneNetworkNode(updated)
		return true, nil
	}
	if !errors.Is(err, store.ErrConflict) {
		return false, err
	}

	latest, err := inventory.GetNetworkNode(ctx, original.ID)
	if err != nil {
		return false, err
	}
	if latest.ManagementIP != original.ManagementIP {
		*current = cloneNetworkNode(latest)
		return false, nil
	}
	merged := mergeObservedNetworkNode(original, persisted, latest)
	if networkNodesEqual(latest, merged) {
		*current = cloneNetworkNode(latest)
		return false, nil
	}
	updated, err = inventory.UpdateNetworkNode(ctx, merged)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			latest, latestErr := inventory.GetNetworkNode(ctx, original.ID)
			if latestErr != nil {
				return false, latestErr
			}
			*current = cloneNetworkNode(latest)
		}
		return false, err
	}
	*current = cloneNetworkNode(updated)
	return true, nil
}

func mergeObservedDevice(original store.Device, observed store.Device, latest store.Device) store.Device {
	merged := cloneDevice(latest)
	merged.Status = observed.Status
	if latest.IPAddress == original.IPAddress {
		merged.IPAddress = observed.IPAddress
	}
	if latest.Hostname == original.Hostname {
		merged.Hostname = observed.Hostname
	}
	if latest.MACAddress == original.MACAddress {
		merged.MACAddress = observed.MACAddress
	}
	mergeObservedMetadata(original.Metadata, observed.Metadata, merged.Metadata)
	return merged
}

func mergeObservedNetworkNode(original store.NetworkNode, observed store.NetworkNode, latest store.NetworkNode) store.NetworkNode {
	merged := cloneNetworkNode(latest)
	merged.Status = observed.Status
	if latest.ManagementIP == original.ManagementIP {
		merged.ManagementIP = observed.ManagementIP
	}
	if latest.MACAddress == original.MACAddress {
		merged.MACAddress = observed.MACAddress
	}
	mergeObservedMetadata(original.Metadata, observed.Metadata, merged.Metadata)
	return merged
}

func mergeObservedMetadata(original map[string]string, observed map[string]string, merged map[string]string) {
	if metadataValueEqual(original, merged, "lastReachablePorts") {
		applyObservedMetadataValue(observed, merged, "lastReachablePorts")
	}
	if metadataValueEqual(original, merged, "panelLink") && metadataValueEqual(original, merged, "panelLinkSource") {
		applyObservedMetadataValue(observed, merged, "panelLink")
		applyObservedMetadataValue(observed, merged, "panelLinkSource")
	}
}

func metadataValueEqual(left map[string]string, right map[string]string, key string) bool {
	leftValue, leftExists := left[key]
	rightValue, rightExists := right[key]
	return leftExists == rightExists && (!leftExists || leftValue == rightValue)
}

func applyObservedMetadataValue(observed map[string]string, merged map[string]string, key string) {
	if value, exists := observed[key]; exists {
		merged[key] = value
	} else {
		delete(merged, key)
	}
}

func devicesEqual(left store.Device, right store.Device) bool {
	return left.Name == right.Name &&
		left.Hostname == right.Hostname &&
		left.Role == right.Role &&
		left.DeviceType == right.DeviceType &&
		left.IPAddress == right.IPAddress &&
		left.MACAddress == right.MACAddress &&
		left.NetworkSegment == right.NetworkSegment &&
		left.Status == right.Status &&
		slices.Equal(left.Tags, right.Tags) &&
		maps.Equal(left.Metadata, right.Metadata)
}

func networkNodesEqual(left store.NetworkNode, right store.NetworkNode) bool {
	return left.Name == right.Name &&
		left.NodeType == right.NodeType &&
		left.ManagementIP == right.ManagementIP &&
		left.MACAddress == right.MACAddress &&
		left.Vendor == right.Vendor &&
		left.Model == right.Model &&
		left.Status == right.Status &&
		slices.Equal(left.Tags, right.Tags) &&
		maps.Equal(left.Metadata, right.Metadata)
}

func cloneDevice(device store.Device) store.Device {
	device.Tags = slices.Clone(device.Tags)
	device.Metadata = maps.Clone(device.Metadata)
	if device.Metadata == nil {
		device.Metadata = map[string]string{}
	}
	return device
}

func cloneDevices(devices []store.Device) []store.Device {
	cloned := make([]store.Device, len(devices))
	for index, device := range devices {
		cloned[index] = cloneDevice(device)
	}
	return cloned
}

func cloneNetworkNode(node store.NetworkNode) store.NetworkNode {
	node.Tags = slices.Clone(node.Tags)
	node.Metadata = maps.Clone(node.Metadata)
	if node.Metadata == nil {
		node.Metadata = map[string]string{}
	}
	return node
}

func cloneNetworkNodes(nodes []store.NetworkNode) []store.NetworkNode {
	cloned := make([]store.NetworkNode, len(nodes))
	for index, node := range nodes {
		cloned[index] = cloneNetworkNode(node)
	}
	return cloned
}

func mergeSummaries(left RefreshSummary, right RefreshSummary) RefreshSummary {
	skipped := left.Skipped + right.Skipped
	return RefreshSummary{
		Checked: left.Checked + right.Checked, Updated: left.Updated + right.Updated,
		Skipped: skipped, Partial: left.Partial || right.Partial || skipped > 0,
		Online: left.Online + right.Online, Degraded: left.Degraded + right.Degraded,
		Offline: left.Offline + right.Offline, Unknown: left.Unknown + right.Unknown,
		MACResolved: left.MACResolved + right.MACResolved,
	}
}

func isSkippableRefreshError(err error) bool {
	return errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict)
}

func accumulateStatus(summary *RefreshSummary, status string) {
	switch status {
	case "online":
		summary.Online++
	case "degraded":
		summary.Degraded++
	case "offline":
		summary.Offline++
	default:
		summary.Unknown++
	}
}

func setReachabilityMetadata(metadata map[string]string, host string, ports []int) {
	if len(ports) == 0 {
		delete(metadata, "lastReachablePorts")
	} else {
		metadata["lastReachablePorts"] = joinPorts(ports)
	}
	stringsPorts := make([]string, len(ports))
	for index, port := range ports {
		stringsPorts[index] = strconv.Itoa(port)
	}
	if panelLink, source, ok := derivePanelLink(metadata, host, stringsPorts); ok {
		if panelLink == "" {
			delete(metadata, "panelLink")
			delete(metadata, "panelLinkSource")
		} else {
			metadata["panelLink"] = panelLink
			metadata["panelLinkSource"] = source
		}
	}
}

func parsePorts(values []string) []int {
	ports := make([]int, 0, len(values))
	for _, value := range values {
		port, err := strconv.Atoi(value)
		if err == nil && port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return ports
}

func resolveIPv4(ctx context.Context, hostname string) (string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip4", strings.TrimSpace(hostname))
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		if canonical, err := canonicalIPv4(address.String()); err == nil {
			return canonical, nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found")
}

func reverseLookup(ctx context.Context, ipAddress string) (string, error) {
	canonical, err := canonicalIPv4(ipAddress)
	if err != nil {
		return "", err
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(lookupCtx, canonical)
	if err != nil || len(names) == 0 {
		return "", fmt.Errorf("reverse lookup failed")
	}
	return strings.TrimSuffix(names[0], "."), nil
}

func pingHost(ctx context.Context, target string, timeout time.Duration) (bool, error) {
	canonical, err := canonicalIPv4(target)
	if err != nil {
		return false, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()

	var command *exec.Cmd
	if runtime.GOOS == "windows" {
		// #nosec G204 -- canonical is a parsed IPv4 literal, never an option.
		command = exec.CommandContext(commandCtx, "ping", "-n", "1", "-w", strconv.Itoa(int(timeout.Milliseconds())), canonical)
	} else {
		seconds := max(1, int(timeout.Seconds()))
		// #nosec G204 -- canonical is a parsed IPv4 literal, never an option.
		command = exec.CommandContext(commandCtx, "ping", "-c", "1", "-W", strconv.Itoa(seconds), canonical)
	}
	err = command.Run()
	if err == nil {
		return true, nil
	}
	if ctxErr := commandCtx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return false, nil
	}
	return false, err
}

func lookupMAC(ctx context.Context, ipAddress string) (string, error) {
	canonical, err := canonicalIPv4(ipAddress)
	if err != nil {
		return "", err
	}
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var output []byte
	if runtime.GOOS == "windows" {
		// #nosec G204 -- canonical is a parsed IPv4 literal, never an option.
		output, err = exec.CommandContext(commandCtx, "arp", "-a", canonical).CombinedOutput()
	} else {
		// #nosec G204 -- canonical is a parsed IPv4 literal, never an option.
		output, err = exec.CommandContext(commandCtx, "arp", "-n", canonical).CombinedOutput()
	}
	if err != nil {
		if ctxErr := commandCtx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", err
	}

	pattern := macAddressColonRegex
	if runtime.GOOS == "windows" {
		pattern = macAddressDashRegex
	}
	match := pattern.FindString(string(output))
	if match == "" {
		return "", fmt.Errorf("no MAC address found")
	}
	return strings.ToUpper(strings.ReplaceAll(match, "-", ":")), nil
}

func probeTCPPorts(ctx context.Context, ipAddress string, ports []int) (bool, bool, []string, error) {
	canonical, err := canonicalIPv4(ipAddress)
	if err != nil {
		return false, false, nil, err
	}
	openPorts := make([]string, 0)
	refused := false
	dialer := net.Dialer{}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return len(openPorts) > 0, refused, openPorts, err
		}
		portCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
		connection, dialErr := dialer.DialContext(portCtx, "tcp", net.JoinHostPort(canonical, strconv.Itoa(port)))
		cancel()
		if dialErr == nil {
			_ = connection.Close()
			openPorts = append(openPorts, strconv.Itoa(port))
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return len(openPorts) > 0, refused, openPorts, ctxErr
		}
		if strings.Contains(strings.ToLower(dialErr.Error()), "connection refused") {
			refused = true
		}
	}
	return len(openPorts) > 0, refused, openPorts, nil
}

func candidatePorts(device store.Device) []int {
	seen := map[int]bool{}
	ports := make([]int, 0)
	add := func(values ...int) {
		for _, value := range values {
			if value > 0 && value <= 65535 && !seen[value] {
				seen[value] = true
				ports = append(ports, value)
			}
		}
	}
	add(443, 80, 22, 445)
	if sshPort, ok := configuredSSHPort(device); ok {
		add(sshPort)
	}
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

func configuredSSHPort(device store.Device) (int, bool) {
	port, err := strconv.Atoi(strings.TrimSpace(device.Metadata["sshPort"]))
	return port, err == nil && port >= 1 && port <= 65535
}

func batchCandidatePorts(devices []store.Device, nodes []store.NetworkNode) []int {
	ports := allCandidatePorts()
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		seen[port] = struct{}{}
	}
	extras := make(map[int]struct{})
	collect := func(candidates []int) {
		for _, port := range candidates {
			if port < 1 || port > 65535 {
				continue
			}
			if _, exists := seen[port]; !exists {
				extras[port] = struct{}{}
			}
		}
	}
	for _, device := range devices {
		collect(candidatePorts(device))
	}
	for _, node := range nodes {
		collect(candidatePortsForNode(node))
	}
	sortedExtras := make([]int, 0, len(extras))
	for port := range extras {
		sortedExtras = append(sortedExtras, port)
	}
	slices.Sort(sortedExtras)
	remaining := max(0, maxBatchScanPorts-len(ports))
	if len(sortedExtras) > remaining {
		sortedExtras = sortedExtras[:remaining]
	}
	return append(ports, sortedExtras...)
}

func candidatePortsForNode(node store.NetworkNode) []int {
	seen := map[int]bool{}
	ports := make([]int, 0)
	add := func(values ...int) {
		for _, value := range values {
			if value > 0 && value <= 65535 && !seen[value] {
				seen[value] = true
				ports = append(ports, value)
			}
		}
	}
	add(443, 80, 22, 53, 161)
	nodeType := strings.ToLower(node.NodeType)
	if strings.Contains(nodeType, "switch") || strings.Contains(nodeType, "access-point") || strings.Contains(nodeType, "ap") {
		add(22, 80, 443, 161)
	}
	if strings.Contains(nodeType, "router") || strings.Contains(nodeType, "gateway") {
		add(22, 80, 443, 53, 161)
	}
	return ports
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
	has443 := slices.Contains(openPorts, "443")
	has80 := slices.Contains(openPorts, "80")
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
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
