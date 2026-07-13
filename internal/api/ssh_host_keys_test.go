package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PhantoNull/home-mesh/internal/config"
	"github.com/PhantoNull/home-mesh/internal/monitor"
	"github.com/PhantoNull/home-mesh/internal/sshclient"
	"github.com/PhantoNull/home-mesh/internal/store"
	"golang.org/x/crypto/ssh"
)

func TestSSHHostKeyProbeAndApproval(t *testing.T) {
	listener, signer := newHostKeyProbeServer(t, 3)
	port := listener.Addr().(*net.TCPAddr).Port

	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	hostKeyStore, err := sshclient.NewHostKeyStore("known_hosts", knownHostsPath)
	if err != nil {
		t.Fatalf("create host-key store: %v", err)
	}
	inventory, err := store.New(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatalf("open inventory: %v", err)
	}
	defer inventory.Close()
	device, err := inventory.AddDevice(context.Background(), store.Device{
		ID:        "device-a",
		Name:      "Probe target",
		IPAddress: "127.0.0.1",
		Metadata:  map[string]string{"sshPort": strconv.Itoa(port)},
	})
	if err != nil {
		t.Fatalf("add device: %v", err)
	}

	bus := monitor.NewEventBus()
	refresher := monitor.NewRefresherWithOptions(inventory, bus, monitor.RefresherOptions{NmapPath: filepath.Join(t.TempDir(), "missing-nmap")})
	handler, err := newRouterWithHostKeyStore(
		config.Config{AppName: "test", AuthDisabled: true, AllowedHosts: []string{"example.com"}},
		inventory,
		refresher,
		bus,
		nil,
		nil,
		hostKeyStore.Callback,
		hostKeyStore,
		newSSHConcurrencyLimits(1, 1),
	)
	if err != nil {
		t.Fatalf("create router: %v", err)
	}

	probeRequest := httptest.NewRequest(http.MethodPost, "/api/devices/"+device.ID+"/ssh-host-key/probe", nil)
	probeResponse := httptest.NewRecorder()
	handler.ServeHTTP(probeResponse, probeRequest)
	if probeResponse.Code != http.StatusOK {
		t.Fatalf("probe status = %d, body = %s", probeResponse.Code, probeResponse.Body.String())
	}
	var probe sshHostKeyResponse
	if err := json.Unmarshal(probeResponse.Body.Bytes(), &probe); err != nil {
		t.Fatalf("decode probe: %v", err)
	}
	if probe.Status != sshclient.HostKeyTrustUnknown || probe.Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("probe response = %+v", probe)
	}

	staleApprovalRequest := httptest.NewRequest(http.MethodPost, "/api/devices/"+device.ID+"/ssh-host-key/approve", strings.NewReader(`{"fingerprint":"SHA256:stale-review"}`))
	staleApprovalRequest.Header.Set("Content-Type", "application/json")
	staleApprovalResponse := httptest.NewRecorder()
	handler.ServeHTTP(staleApprovalResponse, staleApprovalRequest)
	if staleApprovalResponse.Code != http.StatusConflict {
		t.Fatalf("stale approval status = %d, body = %s", staleApprovalResponse.Code, staleApprovalResponse.Body.String())
	}

	approvalRequest := httptest.NewRequest(http.MethodPost, "/api/devices/"+device.ID+"/ssh-host-key/approve", strings.NewReader(`{"fingerprint":"`+probe.Fingerprint+`"}`))
	approvalRequest.Header.Set("Content-Type", "application/json")
	approvalResponse := httptest.NewRecorder()
	handler.ServeHTTP(approvalResponse, approvalRequest)
	if approvalResponse.Code != http.StatusOK {
		t.Fatalf("approval status = %d, body = %s", approvalResponse.Code, approvalResponse.Body.String())
	}
	var approved sshHostKeyResponse
	if err := json.Unmarshal(approvalResponse.Body.Bytes(), &approved); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if approved.Status != sshclient.HostKeyTrustTrusted {
		t.Fatalf("approval response = %+v", approved)
	}
	if err := hostKeyStore.Callback("127.0.0.1:"+strconv.Itoa(port), nil, signer.PublicKey()); err != nil {
		t.Fatalf("approved callback rejected key: %v", err)
	}
}

func newHostKeyProbeServer(t *testing.T, connections int) (net.Listener, ssh.Signer) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create host signer: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &ssh.ServerConfig{NoClientAuth: true}
	server.AddHostKey(signer)
	go func() {
		defer listener.Close()
		for index := 0; index < connections; index++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			serverConnection, _, _, handshakeErr := ssh.NewServerConn(connection, server)
			if handshakeErr == nil {
				_ = serverConnection.Close()
			} else {
				_ = connection.Close()
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
	})
	return listener, signer
}
