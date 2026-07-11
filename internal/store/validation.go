package store

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxIDLength             = 128
	maxNameLength           = 128
	maxTextLength           = 256
	maxSlugLength           = 64
	maxTagCount             = 32
	maxTagLength            = 64
	maxMetadataEntries      = 64
	maxMetadataKeyLength    = 64
	maxMetadataValueLength  = 4096
	maxMetadataEncodedBytes = 32 * 1024
	maxCredentialTextLength = 64 * 1024
)

var (
	idPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	referenceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	slugPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	metadataKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]*$`)

	entityStatuses = map[string]struct{}{
		"unknown":  {},
		"online":   {},
		"degraded": {},
		"offline":  {},
	}
	actionStatuses = map[string]struct{}{
		"running":   {},
		"completed": {},
		"failed":    {},
	}
	relationKinds = map[string]struct{}{
		"device":         {},
		"networkNode":    {},
		"networkSegment": {},
	}
	relationConfidences = map[string]struct{}{
		"manual":   {},
		"observed": {},
		"inferred": {},
	}
)

func canonicalizeDevice(device Device) (Device, error) {
	return canonicalizeDeviceWithIDPolicy(device, false)
}

func canonicalizeExistingDevice(device Device) (Device, error) {
	return canonicalizeDeviceWithIDPolicy(device, true)
}

func canonicalizeDeviceWithIDPolicy(device Device, existing bool) (Device, error) {
	var err error
	if device.ID, err = canonicalEntityID(device.ID, "device id", existing); err != nil {
		return Device{}, err
	}
	if device.Name, err = canonicalText(device.Name, "device name", maxNameLength, true); err != nil {
		return Device{}, err
	}
	if device.Hostname, err = canonicalDNSName(device.Hostname, "hostname"); err != nil {
		return Device{}, err
	}
	if device.Role, err = canonicalOptionalSlug(device.Role, "device role"); err != nil {
		return Device{}, err
	}
	if device.DeviceType, err = canonicalOptionalSlug(device.DeviceType, "device type"); err != nil {
		return Device{}, err
	}
	if device.IPAddress, err = canonicalIP(device.IPAddress, "device IP address"); err != nil {
		return Device{}, err
	}
	if device.MACAddress, err = canonicalMAC(device.MACAddress, "device MAC address"); err != nil {
		return Device{}, err
	}
	if strings.TrimSpace(device.NetworkSegment) != "" {
		if device.NetworkSegment, err = canonicalReferenceID(device.NetworkSegment, "network segment id"); err != nil {
			return Device{}, err
		}
	} else {
		device.NetworkSegment = ""
	}
	if device.Status, err = canonicalEntityStatus(device.Status); err != nil {
		return Device{}, err
	}
	if device.Tags, err = canonicalTags(device.Tags); err != nil {
		return Device{}, err
	}
	if device.Metadata, err = canonicalMetadata(device.Metadata); err != nil {
		return Device{}, err
	}
	return device, nil
}

func canonicalizeNetworkNode(node NetworkNode) (NetworkNode, error) {
	return canonicalizeNetworkNodeWithIDPolicy(node, false)
}

func canonicalizeExistingNetworkNode(node NetworkNode) (NetworkNode, error) {
	return canonicalizeNetworkNodeWithIDPolicy(node, true)
}

func canonicalizeNetworkNodeWithIDPolicy(node NetworkNode, existing bool) (NetworkNode, error) {
	var err error
	if node.ID, err = canonicalEntityID(node.ID, "network node id", existing); err != nil {
		return NetworkNode{}, err
	}
	if node.Name, err = canonicalText(node.Name, "network node name", maxNameLength, true); err != nil {
		return NetworkNode{}, err
	}
	if node.NodeType, err = canonicalSlug(node.NodeType, "network node type"); err != nil {
		return NetworkNode{}, err
	}
	if node.ManagementIP, err = canonicalIP(node.ManagementIP, "management IP address"); err != nil {
		return NetworkNode{}, err
	}
	if node.MACAddress, err = canonicalMAC(node.MACAddress, "network node MAC address"); err != nil {
		return NetworkNode{}, err
	}
	if node.Vendor, err = canonicalText(node.Vendor, "network node vendor", maxTextLength, false); err != nil {
		return NetworkNode{}, err
	}
	if node.Model, err = canonicalText(node.Model, "network node model", maxTextLength, false); err != nil {
		return NetworkNode{}, err
	}
	if node.Status, err = canonicalEntityStatus(node.Status); err != nil {
		return NetworkNode{}, err
	}
	if node.Tags, err = canonicalTags(node.Tags); err != nil {
		return NetworkNode{}, err
	}
	if node.Metadata, err = canonicalMetadata(node.Metadata); err != nil {
		return NetworkNode{}, err
	}
	return node, nil
}

func canonicalizeNetworkSegment(segment NetworkSegment) (NetworkSegment, error) {
	return canonicalizeNetworkSegmentWithIDPolicy(segment, false)
}

func canonicalizeExistingNetworkSegment(segment NetworkSegment) (NetworkSegment, error) {
	return canonicalizeNetworkSegmentWithIDPolicy(segment, true)
}

func canonicalizeNetworkSegmentWithIDPolicy(segment NetworkSegment, existing bool) (NetworkSegment, error) {
	var err error
	if segment.ID, err = canonicalEntityID(segment.ID, "network segment id", existing); err != nil {
		return NetworkSegment{}, err
	}
	if segment.Name, err = canonicalText(segment.Name, "network segment name", maxNameLength, true); err != nil {
		return NetworkSegment{}, err
	}
	if segment.SegmentType, err = canonicalSlug(segment.SegmentType, "network segment type"); err != nil {
		return NetworkSegment{}, err
	}
	if segment.VLANID < 0 || segment.VLANID > 4094 {
		return NetworkSegment{}, validationError("VLAN ID must be between 0 and 4094")
	}

	var prefix netip.Prefix
	if strings.TrimSpace(segment.CIDR) != "" {
		prefix, err = netip.ParsePrefix(strings.TrimSpace(segment.CIDR))
		if err != nil || !prefix.IsValid() {
			return NetworkSegment{}, validationError("network segment CIDR is invalid")
		}
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		segment.CIDR = prefix.String()
	} else {
		segment.CIDR = ""
	}

	if segment.GatewayIP, err = canonicalIP(segment.GatewayIP, "gateway IP address"); err != nil {
		return NetworkSegment{}, err
	}
	if segment.GatewayIP != "" {
		if !prefix.IsValid() {
			return NetworkSegment{}, validationError("gateway IP address requires a network segment CIDR")
		}
		gateway, parseErr := netip.ParseAddr(segment.GatewayIP)
		if parseErr != nil || !prefix.Contains(gateway) {
			return NetworkSegment{}, validationError("gateway IP address must be inside the network segment CIDR")
		}
	}
	if segment.DNSDomain, err = canonicalDNSName(segment.DNSDomain, "DNS domain"); err != nil {
		return NetworkSegment{}, err
	}
	if segment.Metadata, err = canonicalMetadata(segment.Metadata); err != nil {
		return NetworkSegment{}, err
	}
	return segment, nil
}

func canonicalizeRelation(relation Relation) (Relation, error) {
	return canonicalizeRelationWithIDPolicy(relation, false)
}

func canonicalizeExistingRelation(relation Relation) (Relation, error) {
	return canonicalizeRelationWithIDPolicy(relation, true)
}

func canonicalizeRelationWithIDPolicy(relation Relation, existing bool) (Relation, error) {
	var err error
	if relation.ID, err = canonicalEntityID(relation.ID, "relation id", existing); err != nil {
		return Relation{}, err
	}
	relation.SourceKind = strings.TrimSpace(relation.SourceKind)
	if _, ok := relationKinds[relation.SourceKind]; !ok {
		return Relation{}, fmt.Errorf("%w: source relation kind %q is unsupported", ErrInvalidRelationEndpoint, relation.SourceKind)
	}
	if relation.SourceID, err = canonicalReferenceID(relation.SourceID, "source relation id"); err != nil {
		return Relation{}, err
	}
	relation.TargetKind = strings.TrimSpace(relation.TargetKind)
	if _, ok := relationKinds[relation.TargetKind]; !ok {
		return Relation{}, fmt.Errorf("%w: target relation kind %q is unsupported", ErrInvalidRelationEndpoint, relation.TargetKind)
	}
	if relation.TargetID, err = canonicalReferenceID(relation.TargetID, "target relation id"); err != nil {
		return Relation{}, err
	}
	if relation.SourceKind == relation.TargetKind && relation.SourceID == relation.TargetID {
		return Relation{}, validationError("relation source and target must be different")
	}
	if relation.RelationType, err = canonicalSlug(relation.RelationType, "relation type"); err != nil {
		return Relation{}, err
	}
	relation.Confidence = strings.ToLower(strings.TrimSpace(relation.Confidence))
	if relation.Confidence == "" {
		relation.Confidence = "manual"
	}
	if _, ok := relationConfidences[relation.Confidence]; !ok {
		return Relation{}, validationError("relation confidence %q is unsupported", relation.Confidence)
	}
	if relation.Metadata, err = canonicalMetadata(relation.Metadata); err != nil {
		return Relation{}, err
	}
	return relation, nil
}

func canonicalizeSSHCredential(credential SSHCredential) (SSHCredential, error) {
	var err error
	if credential.DeviceID, err = canonicalReferenceID(credential.DeviceID, "credential device id"); err != nil {
		return SSHCredential{}, err
	}
	if credential.Username, err = canonicalText(credential.Username, "SSH username", maxNameLength, true); err != nil {
		return SSHCredential{}, err
	}
	credential.PasswordCiphertext = strings.TrimSpace(credential.PasswordCiphertext)
	credential.PasswordNonce = strings.TrimSpace(credential.PasswordNonce)
	if credential.PasswordCiphertext == "" || credential.PasswordNonce == "" {
		return SSHCredential{}, validationError("SSH ciphertext and nonce are required")
	}
	if !utf8.ValidString(credential.PasswordCiphertext) || strings.ContainsRune(credential.PasswordCiphertext, '\x00') || len(credential.PasswordCiphertext) > maxCredentialTextLength {
		return SSHCredential{}, validationError("SSH ciphertext exceeds %d bytes", maxCredentialTextLength)
	}
	if !utf8.ValidString(credential.PasswordNonce) || strings.ContainsRune(credential.PasswordNonce, '\x00') || len(credential.PasswordNonce) > maxMetadataValueLength {
		return SSHCredential{}, validationError("SSH nonce exceeds %d bytes", maxMetadataValueLength)
	}
	if credential.KeyVersion == 0 {
		credential.KeyVersion = 1
	}
	if credential.KeyVersion < 1 || int64(credential.KeyVersion) > int64(^uint32(0)>>1) {
		return SSHCredential{}, validationError("SSH key version must be between 1 and 2147483647")
	}
	credential.HasPassword = true
	return credential, nil
}

func canonicalizeAction(action Action) (Action, error) {
	return canonicalizeActionWithIDPolicy(action, false)
}

func canonicalizeExistingAction(action Action) (Action, error) {
	return canonicalizeActionWithIDPolicy(action, true)
}

func canonicalizeActionWithIDPolicy(action Action, existing bool) (Action, error) {
	var err error
	if action.ID, err = canonicalEntityID(action.ID, "action id", existing); err != nil {
		return Action{}, err
	}
	if strings.TrimSpace(action.DeviceID) != "" {
		if action.DeviceID, err = canonicalReferenceID(action.DeviceID, "action device id"); err != nil {
			return Action{}, err
		}
	} else {
		action.DeviceID = ""
	}
	if action.ActionType, err = canonicalSlug(action.ActionType, "action type"); err != nil {
		return Action{}, err
	}
	action.Status = strings.ToLower(strings.TrimSpace(action.Status))
	if _, ok := actionStatuses[action.Status]; !ok {
		return Action{}, validationError("action status %q is unsupported", action.Status)
	}
	if action.ResultSummary, err = canonicalText(action.ResultSummary, "action result summary", 2048, false); err != nil {
		return Action{}, err
	}
	if action.Metadata, err = canonicalMetadata(action.Metadata); err != nil {
		return Action{}, err
	}
	return action, nil
}

func canonicalID(value string, field string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", validationError("%s is required", field)
	}
	if len(value) > maxIDLength || !idPattern.MatchString(value) {
		return "", validationError("%s must be a lowercase identifier of at most %d characters", field, maxIDLength)
	}
	return value, nil
}

func canonicalReferenceID(value string, field string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", validationError("%s is required", field)
	}
	if len(value) > maxIDLength || !referenceIDPattern.MatchString(value) {
		return "", validationError("%s must be a safe identifier of at most %d characters", field, maxIDLength)
	}
	return value, nil
}

func canonicalEntityID(value string, field string, existing bool) (string, error) {
	if existing {
		return canonicalReferenceID(value, field)
	}
	return canonicalID(value, field)
}

func canonicalSlug(value string, field string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", validationError("%s is required", field)
	}
	if len(value) > maxSlugLength || !slugPattern.MatchString(value) {
		return "", validationError("%s must be a slug of at most %d characters", field, maxSlugLength)
	}
	return value, nil
}

func canonicalOptionalSlug(value string, field string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	return canonicalSlug(value, field)
}

func canonicalText(value string, field string, maxLength int, required bool) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return "", validationError("%s is required", field)
		}
		return "", nil
	}
	if !utf8.ValidString(value) || len(value) > maxLength {
		return "", validationError("%s must be valid UTF-8 and at most %d bytes", field, maxLength)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", validationError("%s must not contain control characters", field)
		}
	}
	return value, nil
}

func canonicalIP(value string, field string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.IsValid() || address.Zone() != "" {
		return "", validationError("%s is invalid", field)
	}
	return address.Unmap().String(), nil
}

func canonicalMAC(value string, field string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	hardware, err := net.ParseMAC(value)
	if err != nil || len(hardware) != 6 {
		return "", validationError("%s must be a 48-bit Ethernet address", field)
	}
	return strings.ToUpper(hardware.String()), nil
}

func canonicalDNSName(value string, field string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", nil
	}
	if len(value) > 253 {
		return "", validationError("%s exceeds 253 bytes", field)
	}
	if address, err := netip.ParseAddr(value); err == nil && address.IsValid() {
		return "", validationError("%s must be a DNS name, not an IP address", field)
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", validationError("%s is invalid", field)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", validationError("%s is invalid", field)
			}
		}
	}
	return value, nil
}

func canonicalEntityStatus(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = "unknown"
	}
	if _, ok := entityStatuses[value]; !ok {
		return "", validationError("entity status %q is unsupported", value)
	}
	return value, nil
}

func canonicalTags(tags []string) ([]string, error) {
	if len(tags) > maxTagCount {
		return nil, validationError("tag count exceeds %d", maxTagCount)
	}
	result := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || len(tag) > maxTagLength || !slugPattern.MatchString(tag) {
			return nil, validationError("tag %q must be a slug of at most %d characters", tag, maxTagLength)
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}
		result = append(result, tag)
	}
	return result, nil
}

func canonicalMetadata(metadata map[string]string) (map[string]string, error) {
	if len(metadata) > maxMetadataEntries {
		return nil, validationError("metadata entry count exceeds %d", maxMetadataEntries)
	}
	result := make(map[string]string, len(metadata))
	for rawKey, rawValue := range metadata {
		key := strings.TrimSpace(rawKey)
		value := strings.TrimSpace(rawValue)
		if key == "" || len(key) > maxMetadataKeyLength || !metadataKeyPattern.MatchString(key) {
			return nil, validationError("metadata key %q is invalid", key)
		}
		if _, exists := result[key]; exists {
			return nil, validationError("metadata key %q is duplicated after trimming", key)
		}
		if !utf8.ValidString(value) || len(value) > maxMetadataValueLength || containsControlCharacter(value) {
			return nil, validationError("metadata value for %q is invalid or exceeds %d bytes", key, maxMetadataValueLength)
		}
		var err error
		switch key {
		case "panelLink":
			if value != "" {
				value, err = canonicalPanelURL(value)
			}
		case "sshPort":
			if value != "" {
				value, err = canonicalPort(value)
			}
		case "displayOrder":
			if value != "" {
				value, err = canonicalDisplayOrder(value)
			}
		case "panelLinkSource":
			value = strings.ToLower(value)
			if value != "" && value != "manual" && value != "auto" {
				err = validationError("panelLinkSource must be manual or auto")
			}
		case "lastReachablePorts":
			if value != "" {
				value, err = canonicalPortList(value)
			}
		}
		if err != nil {
			return nil, err
		}
		result[key] = value
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, validationError("metadata cannot be encoded: %v", err)
	}
	if len(encoded) > maxMetadataEncodedBytes {
		return nil, validationError("encoded metadata exceeds %d bytes", maxMetadataEncodedBytes)
	}
	return result, nil
}

func containsControlCharacter(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func canonicalPanelURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return "", validationError("panelLink must be an absolute HTTP or HTTPS URL")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", validationError("panelLink must use HTTP or HTTPS")
	}
	if parsed.User != nil {
		return "", validationError("panelLink must not contain credentials")
	}
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String(), nil
}

func canonicalPort(value string) (string, error) {
	port, err := net.LookupPort("tcp", strings.ToLower(strings.TrimSpace(value)))
	if err != nil || port < 1 || port > 65535 {
		return "", validationError("SSH port must be between 1 and 65535")
	}
	return strconv.Itoa(port), nil
}

func canonicalDisplayOrder(value string) (string, error) {
	order, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || order < 0 || order > 1_000_000 {
		return "", validationError("displayOrder must be between 0 and 1000000")
	}
	return strconv.Itoa(order), nil
}

func canonicalPortList(value string) (string, error) {
	parts := strings.Split(value, ",")
	ports := make([]int, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))
	for _, part := range parts {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 {
			return "", validationError("lastReachablePorts must contain TCP ports between 1 and 65535")
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	canonical := make([]string, len(ports))
	for index, port := range ports {
		canonical[index] = strconv.Itoa(port)
	}
	return strings.Join(canonical, ","), nil
}

func validationError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrValidation, fmt.Sprintf(format, args...))
}
