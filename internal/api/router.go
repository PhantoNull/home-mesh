package api

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/PhantoNull/home-mesh/internal/actions"
	"github.com/PhantoNull/home-mesh/internal/config"
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

func NewRouter(cfg config.Config, inventory *store.Store, refresher *monitor.Refresher, secretService *secrets.Service, hostKeyCallback ssh.HostKeyCallback) http.Handler {
	mux := http.NewServeMux()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{
			Name:      cfg.AppName,
			Status:    "ok",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Env:       cfg.Env,
		})
	})

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

	return withCORS(mux)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
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
