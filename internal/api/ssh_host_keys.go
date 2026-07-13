package api

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/PhantoNull/home-mesh/internal/sshclient"
	"github.com/PhantoNull/home-mesh/internal/store"
)

type sshHostKeyResponse struct {
	DeviceID      string `json:"deviceId"`
	Address       string `json:"address"`
	SSHPort       string `json:"sshPort"`
	Status        string `json:"status"`
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	AuthorizedKey string `json:"authorizedKey"`
	Error         string `json:"error,omitempty"`
}

type sshHostKeyApprovalPayload struct {
	Fingerprint string `json:"fingerprint"`
}

func handleSSHHostKeyProbe(w http.ResponseWriter, r *http.Request, inventory *store.Store, hostKeyStore *sshclient.HostKeyStore, probeLimiter *sshRequestLimiter) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if hostKeyStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "SSH host-key enrollment is unavailable"})
		return
	}
	release, ok := acquireSSHRequestSlot(w, r, probeLimiter)
	if !ok {
		return
	}
	defer release()

	deviceID := r.PathValue("id")
	device, err := inventory.GetDevice(r.Context(), deviceID)
	if handleStoreError(w, err, "failed to load device") {
		return
	}
	address, err := resolveSSHAddress(device)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	observation, err := sshclient.ProbeHostKey(r.Context(), address, 10*time.Second)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sshHostKeyResponseFor(deviceID, address, observation, hostKeyStore.TrustStatus(address, observation.Key)))
}

func handleSSHHostKeyApproval(w http.ResponseWriter, r *http.Request, inventory *store.Store, hostKeyStore *sshclient.HostKeyStore, probeLimiter *sshRequestLimiter) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if hostKeyStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "SSH host-key enrollment is unavailable"})
		return
	}
	release, ok := acquireSSHRequestSlot(w, r, probeLimiter)
	if !ok {
		return
	}
	defer release()

	var payload sshHostKeyApprovalPayload
	if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid host-key approval payload") {
		return
	}
	if strings.TrimSpace(payload.Fingerprint) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host-key fingerprint is required"})
		return
	}

	deviceID := r.PathValue("id")
	device, err := inventory.GetDevice(r.Context(), deviceID)
	if handleStoreError(w, err, "failed to load device") {
		return
	}
	address, err := resolveSSHAddress(device)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Probe again at approval time so a key cannot be approved after it has
	// changed between the review shown in the UI and the approval click.
	observation, err := sshclient.ProbeHostKey(r.Context(), address, 10*time.Second)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	response := sshHostKeyResponseFor(deviceID, address, observation, hostKeyStore.TrustStatus(address, observation.Key))
	if strings.TrimSpace(payload.Fingerprint) != observation.Fingerprint {
		response.Status = sshclient.HostKeyTrustChanged
		response.Error = "the host key changed after the probe; review the new fingerprint"
		writeJSON(w, http.StatusConflict, response)
		return
	}
	if response.Status == sshclient.HostKeyTrustChanged {
		response.Error = "a different host key is already trusted for this address; rotate it manually after verification"
		writeJSON(w, http.StatusConflict, response)
		return
	}
	if err := hostKeyStore.Approve(address, observation.Key); err != nil {
		if errors.Is(err, sshclient.ErrHostKeyConflict) {
			response.Status = sshclient.HostKeyTrustChanged
			response.Error = "a different host key is already trusted for this address; rotate it manually after verification"
			writeJSON(w, http.StatusConflict, response)
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	response.Status = sshclient.HostKeyTrustTrusted
	writeJSON(w, http.StatusOK, response)
}

func sshHostKeyResponseFor(deviceID string, address string, observation sshclient.HostKeyObservation, status string) sshHostKeyResponse {
	return sshHostKeyResponse{
		DeviceID:      deviceID,
		Address:       address,
		SSHPort:       sshPortFromAddress(address),
		Status:        status,
		Algorithm:     observation.Algorithm,
		Fingerprint:   observation.Fingerprint,
		AuthorizedKey: observation.AuthorizedKey,
	}
}

func sshPortFromAddress(address string) string {
	if _, port, err := net.SplitHostPort(address); err == nil {
		return port
	}
	return "22"
}
