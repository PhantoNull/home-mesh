package store

import "time"

func seedDevices() []Device {
	return []Device{
		{
			ID:             "dev-nas-01",
			Name:           "Primary NAS",
			Hostname:       "nas.local",
			Role:           "storage",
			DeviceType:     "nas",
			IPAddress:      "192.168.1.20",
			MACAddress:     "AA:BB:CC:DD:EE:20",
			NetworkSegment: "seg-main-lan",
			Status:         "online",
			Tags:           []string{"critical", "media"},
			Metadata:       map[string]string{"discoverySource": "manual"},
		},
		{
			ID:             "dev-pi-01",
			Name:           "Home Mesh Node",
			Hostname:       "mesh-pi.local",
			Role:           "controller",
			DeviceType:     "raspberry-pi",
			IPAddress:      "192.168.1.10",
			MACAddress:     "AA:BB:CC:DD:EE:10",
			NetworkSegment: "seg-main-lan",
			Status:         "online",
			Tags:           []string{"edge", "monitoring"},
			Metadata:       map[string]string{"discoverySource": "self"},
		},
	}
}

func seedNetworkNodes() []NetworkNode {
	return []NetworkNode{
		{
			ID:           "node-router-01",
			Name:         "Main Router",
			NodeType:     "router",
			ManagementIP: "192.168.1.1",
			MACAddress:   "AA:BB:CC:DD:EE:01",
			Vendor:       "Ubiquiti",
			Model:        "UDM-Pro",
			Status:       "online",
			Tags:         []string{"gateway"},
			Metadata:     map[string]string{"site": "home"},
		},
		{
			ID:           "node-switch-01",
			Name:         "Office Switch",
			NodeType:     "switch",
			ManagementIP: "192.168.1.2",
			MACAddress:   "AA:BB:CC:DD:EE:02",
			Vendor:       "TP-Link",
			Model:        "TL-SG108E",
			Status:       "online",
			Tags:         []string{"managed"},
			Metadata:     map[string]string{"room": "office"},
		},
	}
}

func seedNetworkSegments() []NetworkSegment {
	return []NetworkSegment{
		{
			ID:          "seg-main-lan",
			Name:        "Main LAN",
			SegmentType: "lan",
			CIDR:        "192.168.1.0/24",
			VLANID:      1,
			GatewayIP:   "192.168.1.1",
			DNSDomain:   "home.arpa",
			Metadata:    map[string]string{"managed": "true"},
		},
		{
			ID:          "seg-iot",
			Name:        "IoT VLAN",
			SegmentType: "vlan",
			CIDR:        "192.168.50.0/24",
			VLANID:      50,
			GatewayIP:   "192.168.50.1",
			DNSDomain:   "iot.home.arpa",
			Metadata:    map[string]string{"managed": "true"},
		},
	}
}

func seedRelations() []Relation {
	return []Relation{
		{
			ID:           "rel-router-switch",
			SourceKind:   "networkNode",
			SourceID:     "node-router-01",
			TargetKind:   "networkNode",
			TargetID:     "node-switch-01",
			RelationType: "uplink",
			Confidence:   "manual",
			Metadata:     map[string]string{"port": "lan-1"},
		},
		{
			ID:           "rel-pi-segment",
			SourceKind:   "device",
			SourceID:     "dev-pi-01",
			TargetKind:   "networkSegment",
			TargetID:     "seg-main-lan",
			RelationType: "member_of_segment",
			Confidence:   "observed",
			Metadata:     map[string]string{"ip": "192.168.1.10"},
		},
	}
}

func seedActions() []Action {
	now := time.Now().UTC()

	return []Action{
		{
			ID:            "act-seed-wol-01",
			DeviceID:      "dev-nas-01",
			ActionType:    "wake_on_lan",
			Status:        "completed",
			ResultSummary: "Seeded example action.",
			Metadata:      map[string]string{"source": "seed"},
			StartedAt:     now,
			FinishedAt:    now,
		},
	}
}
