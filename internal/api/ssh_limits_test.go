package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/PhantoNull/home-mesh/internal/secrets"
	"github.com/PhantoNull/home-mesh/internal/store"
	"golang.org/x/crypto/ssh"
)

func TestDefaultSSHConcurrencyLimitsMatchOperationalCaps(t *testing.T) {
	t.Parallel()

	limits := newSSHConcurrencyLimits(maxConcurrentSSHCommands, maxConcurrentSSHTerminals)
	if got := cap(limits.commands.slots); got != 32 {
		t.Fatalf("command capacity = %d, want 32", got)
	}
	if got := cap(limits.terminals.slots); got != 16 {
		t.Fatalf("terminal capacity = %d, want 16", got)
	}
}

func TestSSHRequestLimiterHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	limiter := newSSHRequestLimiter(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release, err := limiter.tryAcquire(ctx)
	if !errors.Is(err, context.Canceled) || release != nil {
		t.Fatalf("release = %v, error = %v", release != nil, err)
	}
	if len(limiter.slots) != 0 {
		t.Fatalf("canceled acquisition retained %d slots", len(limiter.slots))
	}
}

func TestSSHHandlersReturn429WhenSaturatedAndReleaseOnEarlyExit(t *testing.T) {
	secretService := newSSHLimitTestSecretService(t)
	limits := newSSHConcurrencyLimits(1, 1)
	handler, inventory := newOCCRouterWithSSH(t, secretService, ssh.InsecureIgnoreHostKey(), limits)
	device, err := inventory.AddDevice(context.Background(), store.Device{ID: "device-a", Name: "NAS"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	ciphertext, nonce, keyVersion, err := secretService.EncryptFor(sshCredentialScope(device.ID), "secret")
	if err != nil {
		t.Fatalf("encrypt credential: %v", err)
	}
	if _, err := inventory.UpsertSSHCredentialAndPort(context.Background(), store.SSHCredential{
		DeviceID:           device.ID,
		Username:           "root",
		PasswordCiphertext: ciphertext,
		PasswordNonce:      nonce,
		KeyVersion:         keyVersion,
	}, "22"); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	releaseCommand, err := limits.commands.tryAcquire(context.Background())
	if err != nil {
		t.Fatalf("reserve command slot: %v", err)
	}
	commandResponse := serveOCCRequest(t, handler, http.MethodPost, "/api/devices/device-a/ssh-command", `{"command":"uptime"}`, "")
	if commandResponse.Code != http.StatusTooManyRequests || commandResponse.Header().Get("Retry-After") != sshLimitRetryAfter {
		t.Fatalf("saturated command status = %d, headers = %v, body = %s", commandResponse.Code, commandResponse.Header(), commandResponse.Body.String())
	}
	actions, err := inventory.ListActions(context.Background())
	if err != nil || len(actions) != 0 {
		t.Fatalf("saturated command created an audit: %+v, %v", actions, err)
	}
	releaseCommand()

	invalidCommandResponse := serveOCCRequest(t, handler, http.MethodPost, "/api/devices/device-a/ssh-command", `{"command":`, "")
	if invalidCommandResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid command status = %d, body = %s", invalidCommandResponse.Code, invalidCommandResponse.Body.String())
	}
	releasedCommandSlot, err := limits.commands.tryAcquire(context.Background())
	if err != nil {
		t.Fatalf("command slot was not released after early exit: %v", err)
	}
	releasedCommandSlot()

	releaseTerminal, err := limits.terminals.tryAcquire(context.Background())
	if err != nil {
		t.Fatalf("reserve terminal slot: %v", err)
	}
	terminalResponse := serveOCCRequest(t, handler, http.MethodGet, "/api/devices/device-a/ssh-terminal", "", "")
	if terminalResponse.Code != http.StatusTooManyRequests || terminalResponse.Header().Get("Retry-After") != sshLimitRetryAfter {
		t.Fatalf("saturated terminal status = %d, headers = %v, body = %s", terminalResponse.Code, terminalResponse.Header(), terminalResponse.Body.String())
	}
	actions, err = inventory.ListActions(context.Background())
	if err != nil || len(actions) != 0 {
		t.Fatalf("saturated terminal created an audit: %+v, %v", actions, err)
	}
	releaseTerminal()

	missingTerminalResponse := serveOCCRequest(t, handler, http.MethodGet, "/api/devices/missing/ssh-terminal", "", "")
	if missingTerminalResponse.Code != http.StatusNotFound {
		t.Fatalf("missing terminal device status = %d, body = %s", missingTerminalResponse.Code, missingTerminalResponse.Body.String())
	}
	releasedTerminalSlot, err := limits.terminals.tryAcquire(context.Background())
	if err != nil {
		t.Fatalf("terminal slot was not released after early exit: %v", err)
	}
	releasedTerminalSlot()
}

func TestSSHTrustUnavailableFailsClosedBeforeCredentialOrExecutionWork(t *testing.T) {
	secretService := newSSHLimitTestSecretService(t)
	handler, inventory := newOCCRouterWithSSH(t, secretService, nil, newSSHConcurrencyLimits(1, 1))
	device, err := inventory.AddDevice(context.Background(), store.Device{ID: "device-a", Name: "NAS"})
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	path := "/api/devices/device-a/ssh-credential"

	getResponse := serveOCCRequest(t, handler, http.MethodGet, path, "", "")
	if getResponse.Code != http.StatusOK {
		t.Fatalf("credential capability status = %d, body = %s", getResponse.Code, getResponse.Body.String())
	}
	var capability sshCredentialResponse
	decodeOCCResponse(t, getResponse, &capability)
	if capability.Available || capability.UnavailableReason != sshUnavailableReason {
		t.Fatalf("credential capability = %+v", capability)
	}

	putResponse := serveOCCRequest(t, handler, http.MethodPut, path, `{
		"username":"root",
		"password":"secret",
		"sshPort":"22"
	}`, formatVersionETag(device.Version))
	if putResponse.Code != http.StatusServiceUnavailable || !strings.Contains(putResponse.Body.String(), "secure SSH access is unavailable") {
		t.Fatalf("credential PUT status = %d, body = %s", putResponse.Code, putResponse.Body.String())
	}
	if _, err := inventory.GetSSHCredential(context.Background(), device.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential persisted while trust was unavailable: %v", err)
	}
	unchanged, err := inventory.GetDevice(context.Background(), device.ID)
	if err != nil || unchanged.Version != device.Version {
		t.Fatalf("device changed after rejected credential PUT: %+v, %v", unchanged, err)
	}

	if _, err := inventory.UpsertSSHCredentialAndPort(context.Background(), store.SSHCredential{
		DeviceID:           device.ID,
		Username:           "root",
		PasswordCiphertext: "invalid-ciphertext",
		PasswordNonce:      "invalid-nonce",
		KeyVersion:         secretService.CurrentVersion(),
	}, "22"); err != nil {
		t.Fatalf("seed invalid credential: %v", err)
	}
	commandResponse := serveOCCRequest(t, handler, http.MethodPost, "/api/devices/device-a/ssh-command", `{"command":"uptime"}`, "")
	if commandResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("command status = %d, body = %s", commandResponse.Code, commandResponse.Body.String())
	}
	terminalResponse := serveOCCRequest(t, handler, http.MethodGet, "/api/devices/device-a/ssh-terminal", "", "")
	if terminalResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("terminal status = %d, body = %s", terminalResponse.Code, terminalResponse.Body.String())
	}
	actions, err := inventory.ListActions(context.Background())
	if err != nil || len(actions) != 0 {
		t.Fatalf("unavailable SSH created audit records: %+v, %v", actions, err)
	}
}

func newSSHLimitTestSecretService(t *testing.T) *secrets.Service {
	t.Helper()
	service, err := secrets.NewKeyring(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x37}, 32)), 1, nil)
	if err != nil {
		t.Fatalf("create secret service: %v", err)
	}
	return service
}
