package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PhantoNull/home-mesh/internal/actions"
	"github.com/PhantoNull/home-mesh/internal/config"
	"github.com/PhantoNull/home-mesh/internal/discovery"
	"github.com/PhantoNull/home-mesh/internal/monitor"
	"github.com/PhantoNull/home-mesh/internal/secrets"
	"github.com/PhantoNull/home-mesh/internal/sshclient"
	"github.com/PhantoNull/home-mesh/internal/store"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type healthResponse struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Env       string `json:"env"`
	NmapAvail bool   `json:"nmapAvailable"`
}

type sshCredentialPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	SSHPort  string `json:"sshPort"`
}

type sshCredentialResponse struct {
	DeviceID    string `json:"deviceId"`
	Username    string `json:"username"`
	HasPassword bool   `json:"hasPassword"`
	KeyVersion  int    `json:"keyVersion"`
	SSHPort     string `json:"sshPort"`
}

type sshCommandPayload struct {
	Command string `json:"command"`
}

type terminalClientMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

type terminalServerMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
}

type discoveryScanPayload struct {
	CIDR string `json:"cidr"`
}

type discoveryScanResponse struct {
	Provider          string                      `json:"provider"`
	CIDR              string                      `json:"cidr"`
	ScannedCIDRs      []string                    `json:"scannedCidrs"`
	Hosts             []discovery.HostMatch       `json:"hosts"`
	SegmentCandidates []discoverySegmentCandidate `json:"segmentCandidates,omitempty"`
}

type discoveryStreamError struct {
	Error string `json:"error"`
}

type discoverySegmentCandidate struct {
	CIDR string `json:"cidr"`
	Name string `json:"name"`
}

type discoveryScanner interface {
	Capabilities() discovery.Capabilities
	ScanCIDR(context.Context, string) (discovery.ScanResult, error)
	ScanCIDRStream(context.Context, string, func(discovery.HostMatch) error) (discovery.ScanResult, error)
}

var errSSETransport = errors.New("sse transport failure")

func NewRouter(cfg config.Config, inventory *store.Store, refresher *monitor.Refresher, bus *monitor.EventBus, discoveryService discoveryScanner, secretService *secrets.Service, hostKeyCallback ssh.HostKeyCallback) (http.Handler, error) {
	requests, err := newRequestMetadata(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{
		CheckOrigin: requests.checkWebSocketOrigin,
	}
	auth, err := newAuthManager(cfg, inventory, requests)
	if err != nil {
		return nil, err
	}

	mux.HandleFunc("/api/auth/session", auth.handleSession)
	mux.HandleFunc("/api/auth/login", auth.handleLogin)
	mux.HandleFunc("/api/auth/logout", auth.handleLogout)

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{
			Name:      cfg.AppName,
			Status:    "ok",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Env:       cfg.Env,
			NmapAvail: refresher.UsingNmap(),
		})
	})

	mux.HandleFunc("/api/events", handleSSE(bus))

	mux.HandleFunc("/api/inventory", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}

		snapshot, err := inventory.Snapshot(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load inventory"})
			return
		}
		for i := range snapshot.Devices {
			snapshot.Devices[i].Status = "unknown"
		}
		for i := range snapshot.NetworkNodes {
			snapshot.NetworkNodes[i].Status = "unknown"
		}

		writeJSON(w, http.StatusOK, snapshot)
	})

	mux.HandleFunc("/api/actions", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			actionHistory, err := inventory.ListActions(r.Context())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load actions"})
				return
			}

			writeJSON(w, http.StatusOK, actionHistory)
		case http.MethodDelete:
			if err := inventory.ClearActions(r.Context()); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear actions"})
				return
			}

			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodDelete)
		}
	})

	mux.HandleFunc("/api/discovery/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}

		writeJSON(w, http.StatusOK, discoveryService.Capabilities())
	})

	mux.HandleFunc("/api/discovery/scan/stream", handleDiscoveryScanStream(inventory, discoveryService))
	mux.HandleFunc("/api/discovery/scan", handleDiscoveryScan(inventory, discoveryService))

	mux.HandleFunc("/api/devices/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}

		result, err := refresher.RefreshAll(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to refresh devices"})
			return
		}
		snapshot, err := inventory.Snapshot(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load refreshed inventory"})
			return
		}
		snapshot.Devices = result.Devices
		snapshot.NetworkNodes = result.NetworkNodes

		writeJSON(w, http.StatusOK, map[string]any{
			"summary":  result.Summary,
			"snapshot": snapshot,
		})
	})

	mux.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			devices, err := inventory.ListDevices(r.Context())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load devices"})
				return
			}

			writeJSON(w, http.StatusOK, devices)
		case http.MethodPost:
			var payload store.Device
			if err := decodeJSON(r, &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device payload"})
				return
			}

			if payload.Name == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device name is required"})
				return
			}
			payload.Status = "unknown"

			device, err := inventory.AddDevice(r.Context(), payload)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create device"})
				return
			}

			_ = refresher.RefreshDeviceByID(r.Context(), device.ID)
			device, _ = inventory.GetDevice(r.Context(), device.ID)

			writeJSON(w, http.StatusCreated, device)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPost)
		}
	})
	mux.HandleFunc("/api/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		switch r.Method {
		case http.MethodGet:
			device, err := inventory.GetDevice(r.Context(), id)
			if handleStoreError(w, err, "failed to load device") {
				return
			}
			writeJSON(w, http.StatusOK, device)
		case http.MethodPut:
			var payload store.Device
			if err := decodeJSON(r, &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device payload"})
				return
			}
			payload.ID = id
			if payload.Name == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device name is required"})
				return
			}
			current, err := inventory.GetDevice(r.Context(), id)
			if handleStoreError(w, err, "failed to load device") {
				return
			}
			payload.Status = current.Status
			device, err := inventory.UpdateDevice(r.Context(), payload)
			if handleStoreError(w, err, "failed to update device") {
				return
			}
			writeJSON(w, http.StatusOK, device)
		case http.MethodDelete:
			if handleStoreError(w, inventory.DeleteDevice(r.Context(), id), "failed to delete device") {
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodDelete)
		}
	})
	mux.HandleFunc("/api/devices/{id}/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}

		id := r.PathValue("id")
		device, err := refresher.RefreshDeviceSnapshotByID(r.Context(), id)
		if handleStoreError(w, err, "failed to refresh device") {
			return
		}

		writeJSON(w, http.StatusOK, device)
	})
	mux.HandleFunc("/api/devices/{id}/wake", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}

		id := r.PathValue("id")
		device, err := inventory.GetDevice(r.Context(), id)
		if handleStoreError(w, err, "failed to load device") {
			return
		}

		if strings.TrimSpace(device.MACAddress) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device has no MAC address configured"})
			return
		}

		startedAt := time.Now().UTC()
		actionRecord := store.Action{
			ID:            generateActionID("wake_on_lan", id, startedAt),
			DeviceID:      id,
			ActionType:    "wake_on_lan",
			Status:        "completed",
			ResultSummary: "Magic packet sent successfully.",
			Metadata: map[string]string{
				"deviceName": device.Name,
				"macAddress": device.MACAddress,
			},
			StartedAt:  startedAt,
			FinishedAt: startedAt,
		}

		if err := actions.SendWakeOnLAN(device.MACAddress); err != nil {
			actionRecord.Status = "failed"
			actionRecord.ResultSummary = err.Error()
		}

		recorded, recordErr := inventory.AddAction(r.Context(), actionRecord)
		if recordErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist wake action"})
			return
		}

		if actionRecord.Status == "failed" {
			writeJSON(w, http.StatusBadGateway, recorded)
			return
		}

		writeJSON(w, http.StatusCreated, recorded)
	})
	mux.HandleFunc("/api/devices/{id}/ssh-credential", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		device, err := inventory.GetDevice(r.Context(), id)
		if handleStoreError(w, err, "failed to load device") {
			return
		}

		switch r.Method {
		case http.MethodGet:
			credential, err := inventory.GetSSHCredential(r.Context(), id)
			if errors.Is(err, store.ErrNotFound) {
				writeJSON(w, http.StatusOK, sshCredentialResponse{
					DeviceID:    id,
					Username:    "",
					HasPassword: false,
					KeyVersion:  1,
					SSHPort:     sshPortForDevice(device),
				})
				return
			}
			if handleStoreError(w, err, "failed to load ssh credential") {
				return
			}

			writeJSON(w, http.StatusOK, sshCredentialResponse{
				DeviceID:    credential.DeviceID,
				Username:    credential.Username,
				HasPassword: credential.HasPassword,
				KeyVersion:  credential.KeyVersion,
				SSHPort:     sshPortForDevice(device),
			})
		case http.MethodPut:
			if secretService == nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ssh credential storage is not configured; set HOME_MESH_MASTER_KEY"})
				return
			}

			var payload sshCredentialPayload
			if err := decodeJSON(r, &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ssh credential payload"})
				return
			}
			if strings.TrimSpace(payload.Username) == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ssh username is required"})
				return
			}
			if payload.Password == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ssh password is required"})
				return
			}
			sshPort, err := normalizeSSHPort(payload.SSHPort)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}

			ciphertext, nonce, err := secretService.Encrypt(payload.Password)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encrypt ssh password"})
				return
			}

			credential, err := inventory.UpsertSSHCredential(r.Context(), store.SSHCredential{
				DeviceID:           id,
				Username:           strings.TrimSpace(payload.Username),
				PasswordCiphertext: ciphertext,
				PasswordNonce:      nonce,
				KeyVersion:         1,
			})
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist ssh credential"})
				return
			}

			if device.Metadata == nil {
				device.Metadata = map[string]string{}
			}
			device.Metadata["sshPort"] = sshPort
			device, err = inventory.UpdateDevice(r.Context(), device)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist ssh port"})
				return
			}

			writeJSON(w, http.StatusOK, sshCredentialResponse{
				DeviceID:    credential.DeviceID,
				Username:    credential.Username,
				HasPassword: credential.HasPassword,
				KeyVersion:  credential.KeyVersion,
				SSHPort:     sshPortForDevice(device),
			})
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPut)
		}
	})
	mux.HandleFunc("/api/devices/{id}/ssh-command", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		if secretService == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ssh execution is not configured; set HOME_MESH_MASTER_KEY"})
			return
		}

		id := r.PathValue("id")
		device, err := inventory.GetDevice(r.Context(), id)
		if handleStoreError(w, err, "failed to load device") {
			return
		}

		credential, err := inventory.GetSSHCredential(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device has no stored ssh credentials"})
			return
		}
		if handleStoreError(w, err, "failed to load ssh credential") {
			return
		}

		var payload sshCommandPayload
		if err := decodeJSON(r, &payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ssh command payload"})
			return
		}
		commandText := strings.TrimSpace(payload.Command)
		if commandText == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ssh command is required"})
			return
		}

		password, err := secretService.Decrypt(credential.PasswordCiphertext, credential.PasswordNonce)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to decrypt ssh password"})
			return
		}

		address, err := resolveSSHAddress(device)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		startedAt := time.Now().UTC()
		actionRecord := store.Action{
			ID:         generateActionID("ssh_command", id, startedAt),
			DeviceID:   id,
			ActionType: "ssh_command",
			Status:     "completed",
			Metadata: map[string]string{
				"deviceName": device.Name,
				"address":    address,
				"command":    commandText,
			},
			StartedAt: startedAt,
		}

		result, runErr := sshclient.RunPasswordCommand(address, credential.Username, password, commandText, 10*time.Second, hostKeyCallback)
		actionRecord.FinishedAt = time.Now().UTC()
		actionRecord.Metadata["output"] = result.Output

		if runErr != nil {
			actionRecord.Status = "failed"
			actionRecord.ResultSummary = summarizeOutput(result.Output, runErr.Error())
		} else {
			actionRecord.ResultSummary = summarizeOutput(result.Output, "SSH command completed.")
		}

		recorded, recordErr := inventory.AddAction(r.Context(), actionRecord)
		if recordErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to persist ssh action"})
			return
		}

		response := map[string]any{
			"id":            recorded.ID,
			"deviceId":      recorded.DeviceID,
			"status":        recorded.Status,
			"resultSummary": recorded.ResultSummary,
			"command":       commandText,
			"output":        result.Output,
			"startedAt":     recorded.StartedAt,
			"finishedAt":    recorded.FinishedAt,
		}

		if recorded.Status == "failed" {
			writeJSON(w, http.StatusBadGateway, response)
			return
		}

		writeJSON(w, http.StatusCreated, response)
	})
	mux.HandleFunc("/api/devices/{id}/ssh-terminal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		if secretService == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ssh execution is not configured; set HOME_MESH_MASTER_KEY"})
			return
		}

		id := r.PathValue("id")
		device, err := inventory.GetDevice(r.Context(), id)
		if handleStoreError(w, err, "failed to load device") {
			return
		}

		credential, err := inventory.GetSSHCredential(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device has no stored ssh credentials"})
			return
		}
		if handleStoreError(w, err, "failed to load ssh credential") {
			return
		}

		password, err := secretService.Decrypt(credential.PasswordCiphertext, credential.PasswordNonce)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to decrypt ssh password"})
			return
		}

		address, err := resolveSSHAddress(device)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		startedAt := time.Now().UTC()
		actionRecord := store.Action{
			ID:         generateActionID("ssh_terminal", id, startedAt),
			DeviceID:   id,
			ActionType: "ssh_terminal",
			Status:     "completed",
			Metadata: map[string]string{
				"deviceName": device.Name,
				"address":    address,
			},
			StartedAt: startedAt,
		}

		session, err := sshclient.StartPasswordTerminal(address, credential.Username, password, 120, 36, 10*time.Second, hostKeyCallback)
		if err != nil {
			actionRecord.Status = "failed"
			actionRecord.FinishedAt = time.Now().UTC()
			actionRecord.ResultSummary = err.Error()
			_, _ = inventory.AddAction(r.Context(), actionRecord)
			_ = socket.WriteJSON(terminalServerMessage{Type: "error", Data: err.Error()})
			_ = socket.Close()
			return
		}
		defer session.Close()
		defer socket.Close()

		send := make(chan terminalServerMessage, 32)
		writerDone := make(chan struct{})
		go func() {
			defer close(writerDone)
			for message := range send {
				if err := socket.WriteJSON(message); err != nil {
					return
				}
			}
		}()

		send <- terminalServerMessage{Type: "status", Data: "connected"}

		streamDone := make(chan struct{}, 2)
		for _, reader := range []io.Reader{session.Stdout(), session.Stderr()} {
			go func(reader io.Reader) {
				defer func() { streamDone <- struct{}{} }()
				buffer := make([]byte, 2048)
				for {
					n, readErr := reader.Read(buffer)
					if n > 0 {
						send <- terminalServerMessage{Type: "output", Data: string(buffer[:n])}
					}
					if readErr != nil {
						return
					}
				}
			}(reader)
		}

		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			defer session.Close()
			for {
				var message terminalClientMessage
				if err := socket.ReadJSON(&message); err != nil {
					return
				}

				switch message.Type {
				case "input":
					if _, err := session.Write([]byte(message.Data)); err != nil {
						send <- terminalServerMessage{Type: "error", Data: err.Error()}
						return
					}
				case "resize":
					if err := session.Resize(message.Cols, message.Rows); err != nil {
						send <- terminalServerMessage{Type: "error", Data: err.Error()}
						return
					}
				case "ping":
					send <- terminalServerMessage{Type: "pong"}
				case "close":
					return
				}
			}
		}()

		waitErr := session.Wait()
		<-readDone
		<-streamDone
		<-streamDone

		actionRecord.FinishedAt = time.Now().UTC()
		if waitErr != nil && !strings.Contains(strings.ToLower(waitErr.Error()), "closed") {
			actionRecord.Status = "failed"
			actionRecord.ResultSummary = waitErr.Error()
			send <- terminalServerMessage{Type: "error", Data: waitErr.Error()}
		} else {
			actionRecord.ResultSummary = "Interactive SSH session closed."
		}
		_, _ = inventory.AddAction(r.Context(), actionRecord)
		send <- terminalServerMessage{Type: "status", Data: "closed"}
		close(send)
		<-writerDone
	})

	mux.HandleFunc("/api/network-nodes", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			nodes, err := inventory.ListNetworkNodes(r.Context())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load network nodes"})
				return
			}

			writeJSON(w, http.StatusOK, nodes)
		case http.MethodPost:
			var payload store.NetworkNode
			if err := decodeJSON(r, &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid network node payload"})
				return
			}

			if payload.Name == "" || payload.NodeType == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "network node name and nodeType are required"})
				return
			}
			payload.Status = "unknown"

			node, err := inventory.AddNetworkNode(r.Context(), payload)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create network node"})
				return
			}

			writeJSON(w, http.StatusCreated, node)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPost)
		}
	})
	mux.HandleFunc("/api/network-nodes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		switch r.Method {
		case http.MethodGet:
			node, err := inventory.GetNetworkNode(r.Context(), id)
			if handleStoreError(w, err, "failed to load network node") {
				return
			}
			writeJSON(w, http.StatusOK, node)
		case http.MethodPut:
			var payload store.NetworkNode
			if err := decodeJSON(r, &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid network node payload"})
				return
			}
			payload.ID = id
			if payload.Name == "" || payload.NodeType == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "network node name and nodeType are required"})
				return
			}
			current, err := inventory.GetNetworkNode(r.Context(), id)
			if handleStoreError(w, err, "failed to load network node") {
				return
			}
			payload.Status = current.Status
			node, err := inventory.UpdateNetworkNode(r.Context(), payload)
			if handleStoreError(w, err, "failed to update network node") {
				return
			}
			writeJSON(w, http.StatusOK, node)
		case http.MethodDelete:
			if handleStoreError(w, inventory.DeleteNetworkNode(r.Context(), id), "failed to delete network node") {
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodDelete)
		}
	})
	mux.HandleFunc("/api/network-nodes/{id}/refresh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}

		id := r.PathValue("id")
		node, err := refresher.RefreshNetworkNodeSnapshotByID(r.Context(), id)
		if handleStoreError(w, err, "failed to refresh network node") {
			return
		}

		writeJSON(w, http.StatusOK, node)
	})

	mux.HandleFunc("/api/network-segments", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			segments, err := inventory.ListNetworkSegments(r.Context())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load network segments"})
				return
			}

			writeJSON(w, http.StatusOK, segments)
		case http.MethodPost:
			var payload store.NetworkSegment
			if err := decodeJSON(r, &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid network segment payload"})
				return
			}

			if payload.Name == "" || payload.SegmentType == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "network segment name and segmentType are required"})
				return
			}

			segment, err := inventory.AddNetworkSegment(r.Context(), payload)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create network segment"})
				return
			}

			writeJSON(w, http.StatusCreated, segment)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPost)
		}
	})
	mux.HandleFunc("/api/network-segments/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		switch r.Method {
		case http.MethodGet:
			segment, err := inventory.GetNetworkSegment(r.Context(), id)
			if handleStoreError(w, err, "failed to load network segment") {
				return
			}
			writeJSON(w, http.StatusOK, segment)
		case http.MethodPut:
			var payload store.NetworkSegment
			if err := decodeJSON(r, &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid network segment payload"})
				return
			}
			payload.ID = id
			if payload.Name == "" || payload.SegmentType == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "network segment name and segmentType are required"})
				return
			}
			segment, err := inventory.UpdateNetworkSegment(r.Context(), payload)
			if handleStoreError(w, err, "failed to update network segment") {
				return
			}
			writeJSON(w, http.StatusOK, segment)
		case http.MethodDelete:
			if handleStoreError(w, inventory.DeleteNetworkSegment(r.Context(), id), "failed to delete network segment") {
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodDelete)
		}
	})

	mux.HandleFunc("/api/relations", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			relations, err := inventory.ListRelations(r.Context())
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load relations"})
				return
			}

			writeJSON(w, http.StatusOK, relations)
		case http.MethodPost:
			var payload store.Relation
			if err := decodeJSON(r, &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid relation payload"})
				return
			}

			if payload.ID == "" || payload.SourceKind == "" || payload.SourceID == "" || payload.TargetKind == "" || payload.TargetID == "" || payload.RelationType == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "relation id, source, target, and relationType are required"})
				return
			}

			relation, err := inventory.AddRelation(r.Context(), payload)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create relation"})
				return
			}

			writeJSON(w, http.StatusCreated, relation)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPost)
		}
	})
	mux.HandleFunc("/api/relations/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		switch r.Method {
		case http.MethodGet:
			relation, err := inventory.GetRelation(r.Context(), id)
			if handleStoreError(w, err, "failed to load relation") {
				return
			}
			writeJSON(w, http.StatusOK, relation)
		case http.MethodPut:
			var payload store.Relation
			if err := decodeJSON(r, &payload); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid relation payload"})
				return
			}
			payload.ID = id
			if payload.SourceKind == "" || payload.SourceID == "" || payload.TargetKind == "" || payload.TargetID == "" || payload.RelationType == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "relation source, target, and relationType are required"})
				return
			}
			relation, err := inventory.UpdateRelation(r.Context(), payload)
			if handleStoreError(w, err, "failed to update relation") {
				return
			}
			writeJSON(w, http.StatusOK, relation)
		case http.MethodDelete:
			if handleStoreError(w, inventory.DeleteRelation(r.Context(), id), "failed to delete relation") {
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodDelete)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"service": cfg.AppName,
			"status":  "bootstrapped",
		})
	})

	return withOriginPolicy(requests, auth.middleware(mux)), nil
}

func handleDiscoveryScanStream(inventory *store.Store, discoveryService discoveryScanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}

		if _, ok := w.(http.Flusher); !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming not supported"})
			return
		}

		filterState, err := loadDiscoveryFilterState(r.Context(), inventory)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load discovery filter state"})
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")

		if err := writeSSEComment(w, "connected"); err != nil {
			return
		}
		if err := flushSSE(w); err != nil {
			return
		}

		result, err := discoveryService.ScanCIDRStream(r.Context(), strings.TrimSpace(r.URL.Query().Get("cidr")), func(host discovery.HostMatch) error {
			if ctxErr := r.Context().Err(); ctxErr != nil {
				return ctxErr
			}
			if !filterState.shouldIncludeHost(host) {
				return nil
			}
			return writeAndFlushSSEJSON(w, "discovery-host", host)
		})
		if err != nil {
			if r.Context().Err() != nil || errors.Is(err, errSSETransport) {
				return
			}

			message := err.Error()
			switch {
			case errors.Is(err, discovery.ErrScanInProgress):
				message = "a discovery scan is already in progress"
			case errors.Is(err, discovery.ErrNmapUnavailable):
				message = "nmap is not available in the current runtime"
			case errors.Is(err, context.DeadlineExceeded):
				message = "discovery scan timed out"
			}
			_ = writeAndFlushSSEJSON(w, "discovery-error", discoveryStreamError{Error: message})
			return
		}

		filteredHosts, segmentCandidates := filterState.finalize(result)
		_ = writeAndFlushSSEJSON(w, "discovery-complete", discoveryScanResponse{
			Provider:          result.Provider,
			CIDR:              result.CIDR,
			ScannedCIDRs:      result.ScannedCIDRs,
			Hosts:             filteredHosts,
			SegmentCandidates: segmentCandidates,
		})
	}
}

func handleDiscoveryScan(inventory *store.Store, discoveryService discoveryScanner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}

		var payload discoveryScanPayload
		if err := decodeJSON(r, &payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid discovery payload"})
			return
		}
		result, err := discoveryService.ScanCIDR(r.Context(), payload.CIDR)
		if errors.Is(err, discovery.ErrScanInProgress) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "a discovery scan is already in progress"})
			return
		}
		if errors.Is(err, discovery.ErrNmapUnavailable) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "nmap is not available in the current runtime"})
			return
		}
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}

		filteredHosts, segmentCandidates, err := filterDiscoveryResults(r.Context(), inventory, result)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to compare discovery results with inventory"})
			return
		}

		writeJSON(w, http.StatusOK, discoveryScanResponse{
			Provider:          result.Provider,
			CIDR:              result.CIDR,
			ScannedCIDRs:      result.ScannedCIDRs,
			Hosts:             filteredHosts,
			SegmentCandidates: segmentCandidates,
		})
	}
}

func writeAndFlushSSEJSON(w http.ResponseWriter, eventName string, payload any) error {
	if err := writeSSEJSONEvent(w, eventName, payload); err != nil {
		return fmt.Errorf("%w: write event: %v", errSSETransport, err)
	}
	if err := flushSSE(w); err != nil {
		return fmt.Errorf("%w: flush event: %v", errSSETransport, err)
	}
	return nil
}

func withOriginPolicy(requests *requestMetadata, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			if !requests.isSameOrigin(r, origin) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request forbidden"})
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *requestMetadata) isSameOrigin(r *http.Request, origin string) bool {
	return isSameOrigin(m.effectiveScheme(r), r.Host, origin)
}

func isSameOrigin(requestScheme string, requestHost string, origin string) bool {
	requestScheme = strings.ToLower(strings.TrimSpace(requestScheme))
	if defaultOriginPort(requestScheme) == "" || requestHost == "" || origin == "" {
		return false
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil || parsedOrigin.Host == "" || parsedOrigin.User != nil || parsedOrigin.RawQuery != "" || parsedOrigin.Fragment != "" || (parsedOrigin.Path != "" && parsedOrigin.Path != "/") {
		return false
	}
	originScheme := strings.ToLower(parsedOrigin.Scheme)
	if defaultOriginPort(originScheme) == "" || originScheme != requestScheme {
		return false
	}

	requestHostname, requestPort, ok := splitHostPort(requestHost)
	if !ok {
		return false
	}

	originHost, originPort, ok := splitHostPort(parsedOrigin.Host)
	if !ok {
		return false
	}

	if requestPort == "" {
		requestPort = defaultOriginPort(requestScheme)
	}
	if originPort == "" {
		originPort = defaultOriginPort(originScheme)
	}

	return strings.EqualFold(requestHostname, originHost) && requestPort == originPort
}

func (m *requestMetadata) checkWebSocketOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	return m.isSameOrigin(r, origin)
}

func splitHostPort(hostport string) (string, string, bool) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", "", false
	}

	if host, port, err := net.SplitHostPort(hostport); err == nil {
		return normalizeHost(host), port, true
	}
	if ip := net.ParseIP(hostport); ip != nil {
		return ip.String(), "", true
	}
	if strings.Contains(hostport, ":") {
		return "", "", false
	}

	return normalizeHost(hostport), "", true
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}

	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func defaultOriginPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain a single JSON object")
		}
		return err
	}

	return nil
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", joinMethods(methods))
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func handleStoreError(w http.ResponseWriter, err error, message string) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
		return true
	}

	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": message})
	return true
}

func generateActionID(actionType string, deviceID string, startedAt time.Time) string {
	sanitizedAction := strings.ReplaceAll(actionType, " ", "_")
	return sanitizedAction + "-" + deviceID + "-" + startedAt.Format("20060102T150405.000000000")
}

func summarizeOutput(output string, fallback string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return fallback
	}

	lines := strings.Split(trimmed, "\n")
	if len(lines[0]) <= 180 {
		return lines[0]
	}

	return lines[0][:180]
}

func resolveSSHAddress(device store.Device) (string, error) {
	port := sshPortForDevice(device)

	host := strings.TrimSpace(device.IPAddress)
	if host == "" {
		host = strings.TrimSpace(device.Hostname)
	}
	if host == "" {
		return "", errors.New("device has no ssh target address")
	}

	return net.JoinHostPort(host, port), nil
}

func sshPortForDevice(device store.Device) string {
	if value := strings.TrimSpace(device.Metadata["sshPort"]); value != "" {
		return value
	}

	return "22"
}

func normalizeSSHPort(value string) (string, error) {
	port := strings.TrimSpace(value)
	if port == "" {
		return "22", nil
	}

	if _, err := net.LookupPort("tcp", port); err != nil {
		return "", errors.New("ssh port must be a valid TCP port")
	}

	return port, nil
}

func joinMethods(methods []string) string {
	if len(methods) == 0 {
		return ""
	}

	result := methods[0]
	for i := 1; i < len(methods); i++ {
		result += ", " + methods[i]
	}

	return result
}

func filterDiscoveryResults(ctx context.Context, inventory *store.Store, result discovery.ScanResult) ([]discovery.HostMatch, []discoverySegmentCandidate, error) {
	filterState, err := loadDiscoveryFilterState(ctx, inventory)
	if err != nil {
		return nil, nil, err
	}
	for _, host := range result.Hosts {
		filterState.shouldIncludeHost(host)
	}
	filteredHosts, segmentCandidates := filterState.finalize(result)
	return filteredHosts, segmentCandidates, nil
}

type discoveryFilterState struct {
	knownIPs        map[string]bool
	knownMACs       map[string]bool
	knownCIDRs      map[string]bool
	filteredHosts   map[string]discovery.HostMatch
	filteredHostIPs []string
}

func loadDiscoveryFilterState(ctx context.Context, inventory *store.Store) (*discoveryFilterState, error) {
	devices, err := inventory.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	nodes, err := inventory.ListNetworkNodes(ctx)
	if err != nil {
		return nil, err
	}
	segments, err := inventory.ListNetworkSegments(ctx)
	if err != nil {
		return nil, err
	}

	knownIPs := map[string]bool{}
	knownMACs := map[string]bool{}
	for _, device := range devices {
		knownIPs[strings.TrimSpace(device.IPAddress)] = true
		knownMACs[strings.ToUpper(strings.TrimSpace(device.MACAddress))] = true
	}
	for _, node := range nodes {
		knownIPs[strings.TrimSpace(node.ManagementIP)] = true
		knownMACs[strings.ToUpper(strings.TrimSpace(node.MACAddress))] = true
	}

	knownCIDRs := map[string]bool{}
	for _, segment := range segments {
		knownCIDRs[strings.TrimSpace(segment.CIDR)] = true
	}

	return &discoveryFilterState{
		knownIPs:      knownIPs,
		knownMACs:     knownMACs,
		knownCIDRs:    knownCIDRs,
		filteredHosts: map[string]discovery.HostMatch{},
	}, nil
}

func (f *discoveryFilterState) shouldIncludeHost(host discovery.HostMatch) bool {
	ip := strings.TrimSpace(host.IPAddress)
	mac := strings.ToUpper(strings.TrimSpace(host.MACAddress))
	if ip == "" {
		return false
	}
	if f.knownIPs[ip] {
		return false
	}
	if mac != "" && f.knownMACs[mac] {
		return false
	}
	if _, exists := f.filteredHosts[ip]; !exists {
		f.filteredHostIPs = append(f.filteredHostIPs, ip)
	}
	f.filteredHosts[ip] = host
	return true
}

func (f *discoveryFilterState) finalize(result discovery.ScanResult) ([]discovery.HostMatch, []discoverySegmentCandidate) {
	filteredHosts := make([]discovery.HostMatch, 0, len(f.filteredHostIPs))
	for _, ip := range f.filteredHostIPs {
		host, ok := f.filteredHosts[ip]
		if !ok {
			continue
		}
		filteredHosts = append(filteredHosts, host)
	}

	segmentCandidates := make([]discoverySegmentCandidate, 0, len(result.ScannedCIDRs))
	for _, cidr := range result.ScannedCIDRs {
		trimmed := strings.TrimSpace(cidr)
		if trimmed == "" || f.knownCIDRs[trimmed] {
			continue
		}
		segmentCandidates = append(segmentCandidates, discoverySegmentCandidate{
			CIDR: trimmed,
			Name: "Discovered " + trimmed,
		})
	}

	return filteredHosts, segmentCandidates
}
