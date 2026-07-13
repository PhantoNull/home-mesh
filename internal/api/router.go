package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PhantoNull/home-mesh/internal/actions"
	"github.com/PhantoNull/home-mesh/internal/config"
	"github.com/PhantoNull/home-mesh/internal/discovery"
	"github.com/PhantoNull/home-mesh/internal/monitor"
	"github.com/PhantoNull/home-mesh/internal/secrets"
	"github.com/PhantoNull/home-mesh/internal/sshclient"
	"github.com/PhantoNull/home-mesh/internal/store"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type healthResponse struct {
	Status string `json:"status"`
}

type sshCredentialPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	SSHPort  string `json:"sshPort"`
}

type sshCredentialResponse struct {
	DeviceID          string `json:"deviceId"`
	Username          string `json:"username"`
	HasPassword       bool   `json:"hasPassword"`
	KeyVersion        int    `json:"keyVersion"`
	SSHPort           string `json:"sshPort"`
	Available         bool   `json:"available"`
	UnavailableReason string `json:"unavailableReason,omitempty"`
}

type sshCommandPayload struct {
	Command string `json:"command"`
}

type inventoryOrderPayload struct {
	Kind  string                     `json:"kind"`
	Items []store.InventoryOrderItem `json:"items"`
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

type inventoryRefresher interface {
	RefreshAll(context.Context) (monitor.RefreshResult, error)
}

var errSSETransport = errors.New("sse transport failure")

const maxJSONBodyBytes int64 = 1 << 20

const (
	synchronousOperationTimeout = 2*time.Minute + 15*time.Second
	synchronousWriteTimeout     = synchronousOperationTimeout + 15*time.Second
)

var errJSONBodyTooLarge = errors.New("request body exceeds maximum size")

func NewRouter(cfg config.Config, inventory *store.Store, refresher *monitor.Refresher, bus *monitor.EventBus, discoveryService discoveryScanner, secretService *secrets.Service, hostKeyCallback ssh.HostKeyCallback) (*Router, error) {
	return newRouter(cfg, inventory, refresher, bus, discoveryService, secretService, hostKeyCallback, newSSHConcurrencyLimits(maxConcurrentSSHCommands, maxConcurrentSSHTerminals))
}

func NewRouterWithHostKeyStore(cfg config.Config, inventory *store.Store, refresher *monitor.Refresher, bus *monitor.EventBus, discoveryService discoveryScanner, secretService *secrets.Service, hostKeyCallback ssh.HostKeyCallback, hostKeyStore *sshclient.HostKeyStore) (*Router, error) {
	return newRouterWithHostKeyStore(cfg, inventory, refresher, bus, discoveryService, secretService, hostKeyCallback, hostKeyStore, newSSHConcurrencyLimits(maxConcurrentSSHCommands, maxConcurrentSSHTerminals))
}

func newRouter(cfg config.Config, inventory *store.Store, refresher *monitor.Refresher, bus *monitor.EventBus, discoveryService discoveryScanner, secretService *secrets.Service, hostKeyCallback ssh.HostKeyCallback, sshLimits *sshConcurrencyLimits) (*Router, error) {
	return newRouterWithHostKeyStore(cfg, inventory, refresher, bus, discoveryService, secretService, hostKeyCallback, nil, sshLimits)
}

func newRouterWithHostKeyStore(cfg config.Config, inventory *store.Store, refresher *monitor.Refresher, bus *monitor.EventBus, discoveryService discoveryScanner, secretService *secrets.Service, hostKeyCallback ssh.HostKeyCallback, hostKeyStore *sshclient.HostKeyStore, sshLimits *sshConcurrencyLimits) (*Router, error) {
	requests, err := newRequestMetadata(cfg.TrustedProxyCIDRs, cfg.AllowedHosts)
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
	terminalConnections := newTerminalConnectionTracker()

	mux.HandleFunc("/api/auth/session", auth.handleSession)
	mux.HandleFunc("/api/auth/login", auth.handleLogin)
	mux.HandleFunc("/api/auth/logout", auth.handleLogout)

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	})

	mux.HandleFunc("/api/ready", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if err := inventory.Ready(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, healthResponse{Status: "not_ready"})
			return
		}
		writeJSON(w, http.StatusOK, healthResponse{Status: "ready"})
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
		writeJSON(w, http.StatusOK, snapshot)
	})

	mux.HandleFunc("/api/inventory/order", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			methodNotAllowed(w, http.MethodPut)
			return
		}

		var payload inventoryOrderPayload
		if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid inventory order payload") {
			return
		}
		if handleStoreError(w, inventory.ReorderInventory(r.Context(), payload.Kind, payload.Items), "failed to reorder inventory") {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/api/actions", handleActionHistory(inventory))

	mux.HandleFunc("/api/discovery/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}

		writeJSON(w, http.StatusOK, discoveryService.Capabilities())
	})

	mux.HandleFunc("/api/discovery/scan/stream", handleDiscoveryScanStream(inventory, discoveryService))
	mux.HandleFunc("/api/discovery/scan", handleDiscoveryScan(inventory, discoveryService))

	mux.HandleFunc("/api/devices/refresh", handleInventoryRefresh(inventory, refresher))

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
			if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid device payload") {
				return
			}

			if payload.Name == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device name is required"})
				return
			}
			payload.Status = "unknown"

			device, err := inventory.AddDevice(r.Context(), payload)
			if handleStoreError(w, err, "failed to create device") {
				return
			}

			_ = refresher.RefreshDeviceByID(r.Context(), device.ID)
			device, _ = inventory.GetDevice(r.Context(), device.ID)

			setVersionETag(w, device.Version)
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
			setVersionETag(w, device.Version)
			writeJSON(w, http.StatusOK, device)
		case http.MethodPut:
			var payload store.Device
			if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid device payload") {
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
			setVersionETag(w, device.Version)
			writeJSON(w, http.StatusOK, device)
		case http.MethodDelete:
			version, ok := requireIfMatchVersion(w, r)
			if !ok {
				return
			}
			if handlePreconditionError(w, inventory.DeleteDeviceVersioned(r.Context(), id, version), "failed to delete device") {
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

		setVersionETag(w, device.Version)
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
			ID:         generateActionID("wake_on_lan"),
			DeviceID:   id,
			ActionType: "wake_on_lan",
			Metadata: map[string]string{
				"deviceName": device.Name,
				"macAddress": device.MACAddress,
			},
			StartedAt: startedAt,
		}

		actionResult, err := executeAuditedAction(r.Context(), inventory, actionRecord, func() auditedOperationOutcome {
			sendErr := actions.SendWakeOnLANContext(r.Context(), device.MACAddress)
			if sendErr != nil {
				return auditedOperationOutcome{
					Err:           sendErr,
					ResultSummary: "Wake-on-LAN failed.",
					Metadata:      map[string]string{"terminationReason": "send_error"},
				}
			}
			return auditedOperationOutcome{
				ResultSummary: "Magic packet sent successfully.",
				Metadata:      map[string]string{"terminationReason": "packet_sent"},
			}
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start wake action"})
			return
		}
		if actionResult.FinalAuditErr != nil {
			log.Printf("finalize wake action %s: %v", actionResult.Action.ID, actionResult.FinalAuditErr)
		}

		response := actionResponse(actionResult.Action, actionResult.FinalAuditErr == nil)
		if actionResult.OperationErr != nil {
			response["error"] = actionResult.OperationErr.Error()
			writeJSON(w, http.StatusBadGateway, response)
			return
		}

		writeJSON(w, http.StatusCreated, response)
	})
	mux.HandleFunc("/api/devices/{id}/ssh-credential", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		device, err := inventory.GetDevice(r.Context(), id)
		if handleStoreError(w, err, "failed to load device") {
			return
		}

		switch r.Method {
		case http.MethodGet:
			available := sshAccessAvailable(secretService, hostKeyCallback)
			unavailableReason := ""
			if !available {
				unavailableReason = sshUnavailableReason
			}
			credential, err := inventory.GetSSHCredential(r.Context(), id)
			if errors.Is(err, store.ErrNotFound) {
				setVersionETag(w, device.Version)
				writeJSON(w, http.StatusOK, sshCredentialResponse{
					DeviceID:          id,
					Username:          "",
					HasPassword:       false,
					KeyVersion:        currentSecretVersion(secretService),
					SSHPort:           sshPortForDevice(device),
					Available:         available,
					UnavailableReason: unavailableReason,
				})
				return
			}
			if handleStoreError(w, err, "failed to load ssh credential") {
				return
			}

			setVersionETag(w, device.Version)
			writeJSON(w, http.StatusOK, sshCredentialResponse{
				DeviceID:          credential.DeviceID,
				Username:          credential.Username,
				HasPassword:       credential.HasPassword,
				KeyVersion:        credential.KeyVersion,
				SSHPort:           sshPortForDevice(device),
				Available:         available,
				UnavailableReason: unavailableReason,
			})
		case http.MethodPut:
			if !sshAccessAvailable(secretService, hostKeyCallback) {
				writeSSHUnavailable(w)
				return
			}
			expectedVersion, ok := requireIfMatchVersion(w, r)
			if !ok {
				return
			}
			if expectedVersion != device.Version {
				setVersionETag(w, device.Version)
				handlePreconditionError(w, store.ErrConflict, "failed to persist ssh credential")
				return
			}
			var payload sshCredentialPayload
			if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid ssh credential payload") {
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

			ciphertext, nonce, keyVersion, err := secretService.EncryptFor(sshCredentialScope(id), payload.Password)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encrypt ssh password"})
				return
			}

			credential, err := inventory.UpsertSSHCredentialAndPortVersioned(r.Context(), store.SSHCredential{
				DeviceID:           id,
				Username:           strings.TrimSpace(payload.Username),
				PasswordCiphertext: ciphertext,
				PasswordNonce:      nonce,
				KeyVersion:         keyVersion,
			}, sshPort, expectedVersion)
			if errors.Is(err, store.ErrConflict) {
				if currentDevice, currentErr := inventory.GetDevice(r.Context(), id); currentErr == nil {
					setVersionETag(w, currentDevice.Version)
				}
			}
			if handlePreconditionError(w, err, "failed to persist ssh credential") {
				return
			}
			setVersionETag(w, expectedVersion+1)

			writeJSON(w, http.StatusOK, sshCredentialResponse{
				DeviceID:    credential.DeviceID,
				Username:    credential.Username,
				HasPassword: credential.HasPassword,
				KeyVersion:  credential.KeyVersion,
				SSHPort:     sshPort,
				Available:   true,
			})
		case http.MethodDelete:
			version, ok := requireIfMatchVersion(w, r)
			if !ok {
				return
			}
			err := inventory.DeleteSSHCredentialAndPort(r.Context(), id, version)
			if errors.Is(err, store.ErrConflict) {
				if currentDevice, currentErr := inventory.GetDevice(r.Context(), id); currentErr == nil {
					setVersionETag(w, currentDevice.Version)
				}
			}
			if handlePreconditionError(w, err, "failed to delete ssh credential") {
				return
			}
			setVersionETag(w, version+1)
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodDelete)
		}
	})
	mux.HandleFunc("/api/devices/{id}/ssh-host-key/probe", func(w http.ResponseWriter, r *http.Request) {
		handleSSHHostKeyProbe(w, r, inventory, hostKeyStore, sshLimits.probes)
	})
	mux.HandleFunc("/api/devices/{id}/ssh-host-key/approve", func(w http.ResponseWriter, r *http.Request) {
		handleSSHHostKeyApproval(w, r, inventory, hostKeyStore, sshLimits.probes)
	})
	mux.HandleFunc("/api/devices/{id}/ssh-command", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		if !sshAccessAvailable(secretService, hostKeyCallback) {
			writeSSHUnavailable(w)
			return
		}
		release, ok := acquireSSHRequestSlot(w, r, sshLimits.commands)
		if !ok {
			return
		}
		defer release()

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
		if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid ssh command payload") {
			return
		}
		commandText := strings.TrimSpace(payload.Command)
		if commandText == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ssh command is required"})
			return
		}

		password, err := decryptAndRotateSSHCredential(r.Context(), inventory, secretService, credential)
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
			ID:         generateActionID("ssh_command"),
			DeviceID:   id,
			ActionType: "ssh_command",
			Metadata: map[string]string{
				"deviceName": device.Name,
				"address":    address,
			},
			StartedAt: startedAt,
		}

		var result sshclient.Result
		actionResult, err := executeAuditedAction(r.Context(), inventory, actionRecord, func() auditedOperationOutcome {
			commandContext, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			var runErr error
			result, runErr = sshclient.RunPasswordCommandContext(
				commandContext,
				address,
				credential.Username,
				password,
				commandText,
				10*time.Second,
				sshclient.DefaultMaxCommandOutput,
				hostKeyCallback,
			)
			summary := "SSH command completed."
			if runErr != nil {
				summary = "SSH command failed."
			}
			return auditedOperationOutcome{
				Err:           runErr,
				ResultSummary: summary,
				Metadata:      sshCommandCompletionMetadata(result, runErr),
			}
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start ssh action"})
			return
		}
		if actionResult.FinalAuditErr != nil {
			log.Printf("finalize SSH command action %s: %v", actionResult.Action.ID, actionResult.FinalAuditErr)
		}

		response := map[string]any{
			"id":              actionResult.Action.ID,
			"deviceId":        actionResult.Action.DeviceID,
			"status":          actionResult.Action.Status,
			"resultSummary":   actionResult.Action.ResultSummary,
			"command":         commandText,
			"output":          result.Output,
			"outputTruncated": result.Truncated,
			"startedAt":       actionResult.Action.StartedAt,
			"finishedAt":      actionResult.Action.FinishedAt,
			"auditPersisted":  actionResult.FinalAuditErr == nil,
		}

		if actionResult.OperationErr != nil {
			response["error"] = actionResult.OperationErr.Error()
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
		if !sshAccessAvailable(secretService, hostKeyCallback) {
			writeSSHUnavailable(w)
			return
		}
		release, ok := acquireSSHRequestSlot(w, r, sshLimits.terminals)
		if !ok {
			return
		}
		defer release()

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

		password, err := decryptAndRotateSSHCredential(r.Context(), inventory, secretService, credential)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to decrypt ssh password"})
			return
		}

		address, err := resolveSSHAddress(device)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		releaseConnection, ok := terminalConnections.acquire()
		if !ok {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "server is shutting down"})
			return
		}
		defer releaseConnection()

		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		startedAt := time.Now().UTC()
		actionRecord := store.Action{
			ID:         generateActionID("ssh_terminal"),
			DeviceID:   id,
			ActionType: "ssh_terminal",
			Metadata: map[string]string{
				"deviceName": device.Name,
				"address":    address,
			},
			StartedAt: startedAt,
		}
		actionRecord, err = startAuditedAction(r.Context(), inventory, actionRecord)
		if err != nil {
			log.Printf("start SSH terminal audit %s: %v", actionRecord.ID, err)
			_ = socket.SetWriteDeadline(time.Now().Add(terminalWriteTimeout))
			_ = socket.WriteJSON(terminalServerMessage{Type: "error", Data: "SSH terminal audit is unavailable."})
			_ = socket.Close()
			return
		}

		session, err := sshclient.StartPasswordTerminalContext(r.Context(), address, credential.Username, password, 120, 36, 10*time.Second, hostKeyCallback)
		if err != nil {
			if _, auditErr := finishAuditedAction(r.Context(), inventory, actionRecord, auditedOperationOutcome{
				Err:           err,
				ResultSummary: "Interactive SSH session failed to connect.",
				Metadata:      map[string]string{"terminationReason": "connect_error"},
			}); auditErr != nil {
				log.Printf("finalize SSH terminal action %s: %v", actionRecord.ID, auditErr)
			}
			_ = socket.SetWriteDeadline(time.Now().Add(terminalWriteTimeout))
			_ = socket.WriteJSON(terminalServerMessage{Type: "error", Data: err.Error()})
			_ = socket.Close()
			return
		}

		result := runTerminalBridge(r.Context(), socket, session)
		resultSummary := "Interactive SSH session closed."
		if result.Err != nil {
			resultSummary = "Interactive SSH session failed."
		}
		if _, auditErr := finishAuditedAction(r.Context(), inventory, actionRecord, auditedOperationOutcome{
			Err:           result.Err,
			ResultSummary: resultSummary,
			Metadata:      map[string]string{"terminationReason": result.TerminationReason},
		}); auditErr != nil {
			log.Printf("finalize SSH terminal action %s: %v", actionRecord.ID, auditErr)
		}
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
			if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid network node payload") {
				return
			}

			if payload.Name == "" || payload.NodeType == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "network node name and nodeType are required"})
				return
			}
			payload.Status = "unknown"

			node, err := inventory.AddNetworkNode(r.Context(), payload)
			if handleStoreError(w, err, "failed to create network node") {
				return
			}

			setVersionETag(w, node.Version)
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
			setVersionETag(w, node.Version)
			writeJSON(w, http.StatusOK, node)
		case http.MethodPut:
			var payload store.NetworkNode
			if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid network node payload") {
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
			setVersionETag(w, node.Version)
			writeJSON(w, http.StatusOK, node)
		case http.MethodDelete:
			version, ok := requireIfMatchVersion(w, r)
			if !ok {
				return
			}
			if handlePreconditionError(w, inventory.DeleteNetworkNodeVersioned(r.Context(), id, version), "failed to delete network node") {
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

		setVersionETag(w, node.Version)
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
			if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid network segment payload") {
				return
			}

			if payload.Name == "" || payload.SegmentType == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "network segment name and segmentType are required"})
				return
			}

			segment, err := inventory.AddNetworkSegment(r.Context(), payload)
			if handleStoreError(w, err, "failed to create network segment") {
				return
			}

			setVersionETag(w, segment.Version)
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
			setVersionETag(w, segment.Version)
			writeJSON(w, http.StatusOK, segment)
		case http.MethodPut:
			var payload store.NetworkSegment
			if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid network segment payload") {
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
			setVersionETag(w, segment.Version)
			writeJSON(w, http.StatusOK, segment)
		case http.MethodDelete:
			version, ok := requireIfMatchVersion(w, r)
			if !ok {
				return
			}
			if handlePreconditionError(w, inventory.DeleteNetworkSegmentVersioned(r.Context(), id, version), "failed to delete network segment") {
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
			if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid relation payload") {
				return
			}

			if payload.ID == "" || payload.SourceKind == "" || payload.SourceID == "" || payload.TargetKind == "" || payload.TargetID == "" || payload.RelationType == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "relation id, source, target, and relationType are required"})
				return
			}

			relation, err := inventory.AddRelation(r.Context(), payload)
			if handleStoreError(w, err, "failed to create relation") {
				return
			}

			setVersionETag(w, relation.Version)
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
			setVersionETag(w, relation.Version)
			writeJSON(w, http.StatusOK, relation)
		case http.MethodPut:
			var payload store.Relation
			if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid relation payload") {
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
			setVersionETag(w, relation.Version)
			writeJSON(w, http.StatusOK, relation)
		case http.MethodDelete:
			version, ok := requireIfMatchVersion(w, r)
			if !ok {
				return
			}
			if handlePreconditionError(w, inventory.DeleteRelationVersioned(r.Context(), id, version), "failed to delete relation") {
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

	return &Router{
		handler:             withOriginPolicy(requests, auth.middleware(mux)),
		terminalConnections: terminalConnections,
	}, nil
}

func handleInventoryRefresh(inventory *store.Store, refresher inventoryRefresher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		r, finish := withSynchronousOperationDeadline(w, r)
		defer finish()

		result, err := refresher.RefreshAll(r.Context())
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "inventory refresh timed out"})
				return
			}
			if errors.Is(err, context.Canceled) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to refresh devices"})
			return
		}
		snapshot, err := inventory.Snapshot(r.Context())
		if err != nil {
			if errors.Is(r.Context().Err(), context.DeadlineExceeded) {
				writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "inventory refresh timed out"})
				return
			}
			if errors.Is(r.Context().Err(), context.Canceled) {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load refreshed inventory"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"summary":  result.Summary,
			"snapshot": snapshot,
		})
	}
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

		cidr := strings.TrimSpace(r.URL.Query().Get("cidr"))
		if err := validateDiscoveryCIDR(cidr); err != nil {
			_ = writeAndFlushSSEJSON(w, "discovery-error", discoveryStreamError{Error: err.Error()})
			return
		}

		result, err := discoveryService.ScanCIDRStream(r.Context(), cidr, func(host discovery.HostMatch) error {
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

			_ = writeAndFlushSSEJSON(w, "discovery-error", discoveryStreamError{Error: discoveryClientMessage(err)})
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
		r, finish := withSynchronousOperationDeadline(w, r)
		defer finish()

		var payload discoveryScanPayload
		if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid discovery payload") {
			return
		}
		if err := validateDiscoveryCIDR(payload.CIDR); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		result, err := discoveryService.ScanCIDR(r.Context(), payload.CIDR)
		if err != nil {
			if errors.Is(r.Context().Err(), context.Canceled) {
				return
			}
			writeJSON(w, discoveryErrorStatus(err), map[string]string{"error": discoveryClientMessage(err)})
			return
		}

		filteredHosts, segmentCandidates, err := filterDiscoveryResults(r.Context(), inventory, result)
		if err != nil {
			if errors.Is(r.Context().Err(), context.DeadlineExceeded) {
				writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "discovery scan timed out"})
				return
			}
			if errors.Is(r.Context().Err(), context.Canceled) {
				return
			}
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

func withSynchronousOperationDeadline(w http.ResponseWriter, r *http.Request) (*http.Request, func()) {
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(synchronousWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		log.Printf("extend synchronous response write deadline: %v", err)
	}
	operationContext, cancel := context.WithTimeout(r.Context(), synchronousOperationTimeout)
	return r.WithContext(operationContext), cancel
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
		if !requests.isAllowedHost(r.Host) {
			writeJSON(w, http.StatusMisdirectedRequest, map[string]string{"error": "request host is not allowed"})
			return
		}
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			if !requests.isSameOrigin(r, origin) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request forbidden"})
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, If-Match")
			w.Header().Set("Access-Control-Expose-Headers", "ETag")
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
	if r.Body == nil {
		return io.EOF
	}
	defer r.Body.Close()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxJSONBodyBytes {
		return errJSONBodyTooLarge
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
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

func handleJSONDecodeError(w http.ResponseWriter, err error, invalidMessage string) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errJSONBodyTooLarge) {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body exceeds 1 MiB"})
		return true
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": invalidMessage})
	return true
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", joinMethods(methods))
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func handleStoreError(w http.ResponseWriter, err error, message string) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
	case errors.Is(err, store.ErrValidation):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "resource version conflict"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": message})
	}
	return true
}

func generateActionID(actionType string) string {
	sanitizedAction := strings.ReplaceAll(actionType, " ", "_")
	return sanitizedAction + "-" + uuid.NewString()
}

func actionResponse(action store.Action, auditPersisted bool) map[string]any {
	return map[string]any{
		"id":             action.ID,
		"deviceId":       action.DeviceID,
		"actionType":     action.ActionType,
		"status":         action.Status,
		"resultSummary":  action.ResultSummary,
		"metadata":       action.Metadata,
		"startedAt":      action.StartedAt,
		"finishedAt":     action.FinishedAt,
		"auditPersisted": auditPersisted,
	}
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

	resolved, err := net.LookupPort("tcp", strings.ToLower(port))
	if err != nil || resolved < 1 || resolved > 65535 {
		return "", errors.New("ssh port must be a valid TCP port")
	}
	return strconv.Itoa(resolved), nil
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

func parseBoundedQueryInt(r *http.Request, name string, fallback int, minimum int, maximum int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, minimum, maximum)
	}
	return value, nil
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
