package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/home-mesh/internal/config"
	"github.com/PhantoNull/home-mesh/internal/monitor"
	"github.com/PhantoNull/home-mesh/internal/secrets"
	"github.com/PhantoNull/home-mesh/internal/store"
	"golang.org/x/crypto/ssh"
)

func TestHealthAndReadinessHaveSeparateMinimalSemantics(t *testing.T) {
	handler, inventory := newOCCRouter(t)

	healthResponse := serveOCCRequest(t, handler, http.MethodGet, "/api/health", "", "")
	if healthResponse.Code != http.StatusOK || healthResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("health status = %d, headers = %v", healthResponse.Code, healthResponse.Header())
	}
	var healthPayload map[string]any
	decodeOCCResponse(t, healthResponse, &healthPayload)
	if len(healthPayload) != 1 || healthPayload["status"] != "ok" {
		t.Fatalf("health payload exposes unexpected details: %v", healthPayload)
	}

	readyResponse := serveOCCRequest(t, handler, http.MethodGet, "/api/ready", "", "")
	if readyResponse.Code != http.StatusOK || readyResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("ready status = %d, body = %s", readyResponse.Code, readyResponse.Body.String())
	}

	if err := inventory.Close(); err != nil {
		t.Fatalf("close inventory: %v", err)
	}
	notReadyResponse := serveOCCRequest(t, handler, http.MethodGet, "/api/ready", "", "")
	if notReadyResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status = %d, body = %s", notReadyResponse.Code, notReadyResponse.Body.String())
	}
	if body := notReadyResponse.Body.String(); strings.Contains(strings.ToLower(body), "database") || strings.Contains(strings.ToLower(body), "schema") {
		t.Fatalf("readiness leaked internal details: %s", body)
	}

	liveAfterFailure := serveOCCRequest(t, handler, http.MethodGet, "/api/health", "", "")
	if liveAfterFailure.Code != http.StatusOK {
		t.Fatalf("liveness depends on readiness: status = %d", liveAfterFailure.Code)
	}
}

func TestInventoryItemResponsesExposeETagsAndStaleUpdateConflicts(t *testing.T) {
	handler, _ := newOCCRouter(t)

	createdResponse := serveOCCRequest(t, handler, http.MethodPost, "/api/network-nodes", `{
		"id": "node-a",
		"name": "Core router",
		"nodeType": "router"
	}`, "")
	if createdResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", createdResponse.Code, createdResponse.Body.String())
	}
	var created store.NetworkNode
	decodeOCCResponse(t, createdResponse, &created)
	if created.Version != 1 || createdResponse.Header().Get("ETag") != `"1"` {
		t.Fatalf("created node = %+v, ETag = %q", created, createdResponse.Header().Get("ETag"))
	}

	getResponse := serveOCCRequest(t, handler, http.MethodGet, "/api/network-nodes/node-a", "", "")
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("ETag") != `"1"` {
		t.Fatalf("GET status = %d, ETag = %q", getResponse.Code, getResponse.Header().Get("ETag"))
	}

	updateBody := `{
		"version": 1,
		"name": "Updated router",
		"nodeType": "router"
	}`
	updatedResponse := serveOCCRequest(t, handler, http.MethodPut, "/api/network-nodes/node-a", updateBody, "")
	if updatedResponse.Code != http.StatusOK {
		t.Fatalf("update status = %d, body = %s", updatedResponse.Code, updatedResponse.Body.String())
	}
	var updated store.NetworkNode
	decodeOCCResponse(t, updatedResponse, &updated)
	if updated.Version != 2 || updatedResponse.Header().Get("ETag") != `"2"` {
		t.Fatalf("updated node = %+v, ETag = %q", updated, updatedResponse.Header().Get("ETag"))
	}

	conflictResponse := serveOCCRequest(t, handler, http.MethodPut, "/api/network-nodes/node-a", updateBody, "")
	if conflictResponse.Code != http.StatusConflict {
		t.Fatalf("stale update status = %d, body = %s", conflictResponse.Code, conflictResponse.Body.String())
	}
}

func TestInventoryValidationErrorsMapToBadRequest(t *testing.T) {
	handler, inventory := newOCCRouter(t)

	createResponse := serveOCCRequest(t, handler, http.MethodPost, "/api/network-segments", `{
		"id": "segment-a",
		"name": "LAN",
		"segmentType": "lan",
		"cidr": "not-a-cidr"
	}`, "")
	if createResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid create status = %d, body = %s", createResponse.Code, createResponse.Body.String())
	}

	segment, err := inventory.AddNetworkSegment(context.Background(), store.NetworkSegment{
		ID:          "segment-a",
		Name:        "LAN",
		SegmentType: "lan",
		CIDR:        "192.168.10.0/24",
	})
	if err != nil {
		t.Fatalf("seed segment: %v", err)
	}
	updateResponse := serveOCCRequest(t, handler, http.MethodPut, "/api/network-segments/segment-a", `{
		"version": 1,
		"name": "LAN",
		"segmentType": "lan",
		"cidr": "still-not-a-cidr"
	}`, "")
	if updateResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid update status = %d, body = %s, segment = %+v", updateResponse.Code, updateResponse.Body.String(), segment)
	}
}

func TestInventoryOrderMapsValidationAndConflicts(t *testing.T) {
	handler, inventory := newOCCRouter(t)

	invalidResponse := serveOCCRequest(t, handler, http.MethodPut, "/api/inventory/order", `{
		"kind": "unsupported",
		"items": []
	}`, "")
	if invalidResponse.Code != http.StatusBadRequest {
		t.Fatalf("invalid order status = %d, body = %s", invalidResponse.Code, invalidResponse.Body.String())
	}

	node, err := inventory.AddNetworkNode(context.Background(), store.NetworkNode{
		ID:       "node-a",
		Name:     "Router",
		NodeType: "router",
	})
	if err != nil {
		t.Fatalf("seed order node: %v", err)
	}
	orderBody := `{
		"kind": "networkNode",
		"items": [{"id": "node-a", "version": 1}]
	}`
	orderedResponse := serveOCCRequest(t, handler, http.MethodPut, "/api/inventory/order", orderBody, "")
	if orderedResponse.Code != http.StatusNoContent {
		t.Fatalf("order status = %d, body = %s, node = %+v", orderedResponse.Code, orderedResponse.Body.String(), node)
	}

	conflictResponse := serveOCCRequest(t, handler, http.MethodPut, "/api/inventory/order", orderBody, "")
	if conflictResponse.Code != http.StatusConflict {
		t.Fatalf("stale order status = %d, body = %s", conflictResponse.Code, conflictResponse.Body.String())
	}
}

func TestJSONBodyLimitRejectsValidPayloadWithOversizedPadding(t *testing.T) {
	handler, _ := newOCCRouter(t)
	body := `{"kind":"device","items":[]}` + strings.Repeat(" ", int(maxJSONBodyBytes))
	request := httptest.NewRequest(http.MethodPut, "/api/inventory/order", strings.NewReader(body))
	request.ContentLength = -1
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized JSON status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestInventoryRefreshReturnsPointInTimeSnapshot(t *testing.T) {
	_, inventory := newOCCRouter(t)
	ctx := context.Background()
	existing, err := inventory.AddDevice(ctx, store.Device{ID: "existing-device", Name: "Existing"})
	if err != nil {
		t.Fatalf("seed existing device: %v", err)
	}

	refresher := refreshAllFunc(func(ctx context.Context) (monitor.RefreshResult, error) {
		if _, err := inventory.AddDevice(ctx, store.Device{ID: "concurrent-device", Name: "Concurrent"}); err != nil {
			return monitor.RefreshResult{}, err
		}
		return monitor.RefreshResult{
			Summary: monitor.RefreshSummary{Checked: 1},
			Devices: []store.Device{existing},
		}, nil
	})
	response := httptest.NewRecorder()
	handleInventoryRefresh(inventory, refresher).ServeHTTP(
		response,
		httptest.NewRequest(http.MethodPost, "/api/devices/refresh", nil),
	)

	if response.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		Summary  monitor.RefreshSummary  `json:"summary"`
		Snapshot store.InventorySnapshot `json:"snapshot"`
	}
	decodeOCCResponse(t, response, &payload)
	if payload.Summary.Checked != 1 {
		t.Fatalf("refresh summary = %+v", payload.Summary)
	}
	found := false
	for _, device := range payload.Snapshot.Devices {
		if device.ID == "concurrent-device" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("point-in-time snapshot lost concurrently created device: %+v", payload.Snapshot.Devices)
	}
}

func TestSSHCredentialDeleteRequiresCurrentDeviceETag(t *testing.T) {
	handler, inventory := newOCCRouter(t)
	ctx := context.Background()
	device, err := inventory.AddDevice(ctx, store.Device{ID: "device-a", Name: "NAS"})
	if err != nil {
		t.Fatalf("seed credential device: %v", err)
	}
	const secretSentinel = "ciphertext-secret-sentinel"
	if _, err := inventory.UpsertSSHCredentialAndPort(ctx, store.SSHCredential{
		DeviceID:           device.ID,
		Username:           "root",
		PasswordCiphertext: secretSentinel,
		PasswordNonce:      "nonce-secret-sentinel",
		KeyVersion:         1,
	}, "2222"); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	current, err := inventory.GetDevice(ctx, device.ID)
	if err != nil {
		t.Fatalf("load credential device: %v", err)
	}
	path := "/api/devices/device-a/ssh-credential"

	getResponse := serveOCCRequest(t, handler, http.MethodGet, path, "", "")
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("ETag") != formatVersionETag(current.Version) {
		t.Fatalf("credential GET status = %d, ETag = %q", getResponse.Code, getResponse.Header().Get("ETag"))
	}
	if strings.Contains(getResponse.Body.String(), secretSentinel) {
		t.Fatalf("credential GET exposed ciphertext: %s", getResponse.Body.String())
	}

	missingResponse := serveOCCRequest(t, handler, http.MethodDelete, path, "", "")
	if missingResponse.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match status = %d, body = %s", missingResponse.Code, missingResponse.Body.String())
	}
	staleResponse := serveOCCRequest(t, handler, http.MethodDelete, path, "", formatVersionETag(device.Version))
	if staleResponse.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match status = %d, body = %s", staleResponse.Code, staleResponse.Body.String())
	}
	if strings.Contains(staleResponse.Body.String(), secretSentinel) {
		t.Fatalf("stale delete exposed ciphertext: %s", staleResponse.Body.String())
	}

	deletedResponse := serveOCCRequest(t, handler, http.MethodDelete, path, "", formatVersionETag(current.Version))
	if deletedResponse.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, body = %s", deletedResponse.Code, deletedResponse.Body.String())
	}
	if _, err := inventory.GetSSHCredential(ctx, device.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential still exists: %v", err)
	}
	updated, err := inventory.GetDevice(ctx, device.ID)
	if err != nil || updated.Version != current.Version+1 || updated.Metadata["sshPort"] != "" {
		t.Fatalf("device after credential delete = %+v, %v", updated, err)
	}
}

func TestSSHCredentialPutReturnsCanonicalPortAndNeverEchoesPassword(t *testing.T) {
	secretService, err := secrets.NewKeyring(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)), 2, nil)
	if err != nil {
		t.Fatalf("create secrets service: %v", err)
	}
	handler, inventory := newOCCRouterWithSecrets(t, secretService)
	device, err := inventory.AddDevice(context.Background(), store.Device{ID: "device-a", Name: "NAS"})
	if err != nil {
		t.Fatalf("seed credential device: %v", err)
	}
	const passwordSentinel = "password-secret-sentinel"
	path := "/api/devices/device-a/ssh-credential"
	body := `{
		"username": "root",
		"password": "password-secret-sentinel",
		"sshPort": "ssh"
	}`

	missingResponse := serveOCCRequest(t, handler, http.MethodPut, path, body, "")
	if missingResponse.Code != http.StatusPreconditionRequired {
		t.Fatalf("credential PUT without If-Match status = %d, body = %s", missingResponse.Code, missingResponse.Body.String())
	}
	if _, err := inventory.GetSSHCredential(context.Background(), device.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential persisted without If-Match: %v", err)
	}

	staleResponse := serveOCCRequest(t, handler, http.MethodPut, path, body, formatVersionETag(device.Version+1))
	if staleResponse.Code != http.StatusPreconditionFailed {
		t.Fatalf("credential PUT with stale If-Match status = %d, body = %s", staleResponse.Code, staleResponse.Body.String())
	}

	putResponse := serveOCCRequest(t, handler, http.MethodPut, path, body, formatVersionETag(device.Version))
	if putResponse.Code != http.StatusOK || putResponse.Header().Get("ETag") != formatVersionETag(device.Version+1) {
		t.Fatalf("credential PUT status = %d, ETag = %q, body = %s", putResponse.Code, putResponse.Header().Get("ETag"), putResponse.Body.String())
	}
	if body := putResponse.Body.String(); strings.Contains(body, passwordSentinel) || !strings.Contains(body, `"sshPort":"22"`) {
		t.Fatalf("credential PUT response is not canonical or exposed password: %s", body)
	}

	getResponse := serveOCCRequest(t, handler, http.MethodGet, path, "", "")
	if getResponse.Code != http.StatusOK || strings.Contains(getResponse.Body.String(), passwordSentinel) || !strings.Contains(getResponse.Body.String(), `"sshPort":"22"`) {
		t.Fatalf("credential GET response = %d, %s", getResponse.Code, getResponse.Body.String())
	}

	invalidUsername := strings.Repeat("x", 300)
	invalidResponse := serveOCCRequest(t, handler, http.MethodPut, path, `{
		"username": "`+invalidUsername+`",
		"password": "password-secret-sentinel",
		"sshPort": "22"
	}`, formatVersionETag(device.Version+1))
	if invalidResponse.Code != http.StatusBadRequest || strings.Contains(invalidResponse.Body.String(), passwordSentinel) {
		t.Fatalf("invalid credential status = %d, body = %s", invalidResponse.Code, invalidResponse.Body.String())
	}
}

type refreshAllFunc func(context.Context) (monitor.RefreshResult, error)

func (f refreshAllFunc) RefreshAll(ctx context.Context) (monitor.RefreshResult, error) {
	return f(ctx)
}

func TestInventoryDeletesRequireMatchingStrongETag(t *testing.T) {
	for _, kind := range []string{"device", "network-node", "network-segment", "relation"} {
		t.Run(kind, func(t *testing.T) {
			handler, inventory := newOCCRouter(t)
			path, version := seedOCCResource(t, inventory, kind)

			getResponse := serveOCCRequest(t, handler, http.MethodGet, path, "", "")
			if getResponse.Code != http.StatusOK || getResponse.Header().Get("ETag") != formatVersionETag(version) {
				t.Fatalf("GET status = %d, ETag = %q", getResponse.Code, getResponse.Header().Get("ETag"))
			}

			missingResponse := serveOCCRequest(t, handler, http.MethodDelete, path, "", "")
			if missingResponse.Code != http.StatusPreconditionRequired {
				t.Fatalf("missing If-Match status = %d, body = %s", missingResponse.Code, missingResponse.Body.String())
			}

			malformedResponse := serveOCCRequest(t, handler, http.MethodDelete, path, "", `W/"1"`)
			if malformedResponse.Code != http.StatusPreconditionRequired {
				t.Fatalf("malformed If-Match status = %d, body = %s", malformedResponse.Code, malformedResponse.Body.String())
			}

			staleResponse := serveOCCRequest(t, handler, http.MethodDelete, path, "", formatVersionETag(version+1))
			if staleResponse.Code != http.StatusPreconditionFailed {
				t.Fatalf("stale If-Match status = %d, body = %s", staleResponse.Code, staleResponse.Body.String())
			}

			deletedResponse := serveOCCRequest(t, handler, http.MethodDelete, path, "", formatVersionETag(version))
			if deletedResponse.Code != http.StatusNoContent {
				t.Fatalf("matching If-Match status = %d, body = %s", deletedResponse.Code, deletedResponse.Body.String())
			}
		})
	}
}

func TestParseIfMatchVersionRejectsNonCanonicalValidators(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		values  []string
		want    int64
		wantErr bool
	}{
		{name: "valid", values: []string{`"42"`}, want: 42},
		{name: "missing", wantErr: true},
		{name: "weak", values: []string{`W/"42"`}, wantErr: true},
		{name: "wildcard", values: []string{"*"}, wantErr: true},
		{name: "unquoted", values: []string{"42"}, wantErr: true},
		{name: "list", values: []string{`"41", "42"`}, wantErr: true},
		{name: "duplicate", values: []string{`"42"`, `"42"`}, wantErr: true},
		{name: "zero", values: []string{`"0"`}, wantErr: true},
		{name: "noncanonical", values: []string{`"042"`}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseIfMatchVersion(test.values)
			if test.wantErr {
				if err == nil {
					t.Fatalf("version = %d, want error", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("version = %d, error = %v, want %d", got, err, test.want)
			}
		})
	}
}

func newOCCRouter(t *testing.T) (http.Handler, *store.Store) {
	return newOCCRouterWithSecrets(t, nil)
}

func newOCCRouterWithSecrets(t *testing.T, secretService *secrets.Service) (http.Handler, *store.Store) {
	return newOCCRouterWithSSH(t, secretService, ssh.InsecureIgnoreHostKey(), nil)
}

func newOCCRouterWithSSH(t *testing.T, secretService *secrets.Service, hostKeyCallback ssh.HostKeyCallback, sshLimits *sshConcurrencyLimits) (http.Handler, *store.Store) {
	t.Helper()

	inventory, err := store.New(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatalf("open inventory: %v", err)
	}
	t.Cleanup(func() { _ = inventory.Close() })

	bus := monitor.NewEventBus()
	refresher := monitor.NewRefresherWithOptions(inventory, bus, monitor.RefresherOptions{
		NmapPath: filepath.Join(t.TempDir(), "missing-nmap"),
	})
	if sshLimits == nil {
		sshLimits = newSSHConcurrencyLimits(maxConcurrentSSHCommands, maxConcurrentSSHTerminals)
	}
	handler, err := newRouter(config.Config{AppName: "test", AuthDisabled: true, AllowedHosts: []string{"example.com"}}, inventory, refresher, bus, nil, secretService, hostKeyCallback, sshLimits)
	if err != nil {
		t.Fatalf("create router: %v", err)
	}
	return handler, inventory
}

func seedOCCResource(t *testing.T, inventory *store.Store, kind string) (string, int64) {
	t.Helper()
	ctx := context.Background()

	switch kind {
	case "device":
		device, err := inventory.AddDevice(ctx, store.Device{ID: "device-a", Name: "NAS"})
		if err != nil {
			t.Fatalf("seed device: %v", err)
		}
		return "/api/devices/" + device.ID, device.Version
	case "network-node":
		node, err := inventory.AddNetworkNode(ctx, store.NetworkNode{ID: "node-a", Name: "Router", NodeType: "router"})
		if err != nil {
			t.Fatalf("seed network node: %v", err)
		}
		return "/api/network-nodes/" + node.ID, node.Version
	case "network-segment":
		segment, err := inventory.AddNetworkSegment(ctx, store.NetworkSegment{ID: "segment-a", Name: "LAN", SegmentType: "lan"})
		if err != nil {
			t.Fatalf("seed network segment: %v", err)
		}
		return "/api/network-segments/" + segment.ID, segment.Version
	case "relation":
		device, err := inventory.AddDevice(ctx, store.Device{ID: "device-a", Name: "NAS"})
		if err != nil {
			t.Fatalf("seed relation device: %v", err)
		}
		node, err := inventory.AddNetworkNode(ctx, store.NetworkNode{ID: "node-a", Name: "Router", NodeType: "router"})
		if err != nil {
			t.Fatalf("seed relation node: %v", err)
		}
		relation, err := inventory.AddRelation(ctx, store.Relation{
			ID:           "relation-a",
			SourceKind:   "device",
			SourceID:     device.ID,
			TargetKind:   "networkNode",
			TargetID:     node.ID,
			RelationType: "connected_to",
			Confidence:   "manual",
		})
		if err != nil {
			t.Fatalf("seed relation: %v", err)
		}
		return "/api/relations/" + relation.ID, relation.Version
	default:
		t.Fatalf("unsupported resource kind %q", kind)
		return "", 0
	}
}

func serveOCCRequest(t *testing.T, handler http.Handler, method string, path string, body string, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeOCCResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
