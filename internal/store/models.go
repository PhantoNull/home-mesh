package store

import "time"

type Device struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Hostname       string            `json:"hostname"`
	Role           string            `json:"role"`
	DeviceType     string            `json:"deviceType"`
	IPAddress      string            `json:"ipAddress"`
	MACAddress     string            `json:"macAddress"`
	NetworkSegment string            `json:"networkSegment"`
	Status         string            `json:"status"`
	Tags           []string          `json:"tags"`
	Metadata       map[string]string `json:"metadata"`
	CreatedAt      time.Time         `json:"createdAt"`
	UpdatedAt      time.Time         `json:"updatedAt"`
}

type NetworkNode struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	NodeType     string            `json:"nodeType"`
	ManagementIP string            `json:"managementIp"`
	MACAddress   string            `json:"macAddress"`
	Vendor       string            `json:"vendor"`
	Model        string            `json:"model"`
	Status       string            `json:"status"`
	Tags         []string          `json:"tags"`
	Metadata     map[string]string `json:"metadata"`
	CreatedAt    time.Time         `json:"createdAt"`
	UpdatedAt    time.Time         `json:"updatedAt"`
}

type NetworkSegment struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	SegmentType string            `json:"segmentType"`
	CIDR        string            `json:"cidr"`
	VLANID      int               `json:"vlanId"`
	GatewayIP   string            `json:"gatewayIp"`
	DNSDomain   string            `json:"dnsDomain"`
	Metadata    map[string]string `json:"metadata"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
}

type Relation struct {
	ID           string            `json:"id"`
	SourceKind   string            `json:"sourceKind"`
	SourceID     string            `json:"sourceId"`
	TargetKind   string            `json:"targetKind"`
	TargetID     string            `json:"targetId"`
	RelationType string            `json:"relationType"`
	Confidence   string            `json:"confidence"`
	Metadata     map[string]string `json:"metadata"`
	ObservedAt   time.Time         `json:"observedAt"`
}

type InventorySnapshot struct {
	Devices         []Device         `json:"devices"`
	NetworkNodes    []NetworkNode    `json:"networkNodes"`
	NetworkSegments []NetworkSegment `json:"networkSegments"`
	Relations       []Relation       `json:"relations"`
	Actions         []Action         `json:"actions"`
}

type Action struct {
	ID            string            `json:"id"`
	DeviceID      string            `json:"deviceId"`
	ActionType    string            `json:"actionType"`
	Status        string            `json:"status"`
	ResultSummary string            `json:"resultSummary"`
	Metadata      map[string]string `json:"metadata"`
	StartedAt     time.Time         `json:"startedAt"`
	FinishedAt    time.Time         `json:"finishedAt"`
}

type SSHCredential struct {
	DeviceID           string    `json:"deviceId"`
	Username           string    `json:"username"`
	PasswordCiphertext string    `json:"-"`
	PasswordNonce      string    `json:"-"`
	HasPassword        bool      `json:"hasPassword"`
	KeyVersion         int       `json:"keyVersion"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

type AdminAccount struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}
