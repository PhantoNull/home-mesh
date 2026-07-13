package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestHostKeyCallbackModes(t *testing.T) {
	t.Parallel()

	if _, err := HostKeyCallback("insecure", ""); err == nil {
		t.Fatal("insecure mode must be rejected")
	}

	if _, err := HostKeyCallback("known_hosts", ""); err == nil {
		t.Fatal("known_hosts mode without a path should fail")
	} else if !errors.Is(err, ErrHostKeyTrustUnavailable) {
		t.Fatalf("missing known_hosts error = %v", err)
	}
}

func TestHostKeyCallbackAcceptsProtectedRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HostKeyCallback("known_hosts", path); err != nil {
		t.Fatalf("protected known_hosts file: %v", err)
	}
}

func TestHostKeyCallbackRejectsNonRegularAndWritableFiles(t *testing.T) {
	directory := t.TempDir()
	if _, err := HostKeyCallback("known_hosts", directory); err == nil {
		t.Fatal("known_hosts directory was accepted")
	}

	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err == nil {
		if _, err := HostKeyCallback("known_hosts", link); err == nil {
			t.Fatal("known_hosts symlink was accepted")
		}
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(target, 0o622); err != nil {
			t.Fatal(err)
		}
		if _, err := HostKeyCallback("known_hosts", target); err == nil {
			t.Fatal("group/world-writable known_hosts file was accepted")
		}
	}
}

func TestHostKeyStoreApprovesUnknownKeyAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("# managed trust\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewHostKeyStore("known_hosts", path)
	if err != nil {
		t.Fatalf("create host-key store: %v", err)
	}
	key := testHostKey(t)
	address := "192.0.2.65:22"
	if status := store.TrustStatus(address, key); status != HostKeyTrustUnknown {
		t.Fatalf("initial trust status = %q, want unknown", status)
	}
	if err := store.Approve(address, key); err != nil {
		t.Fatalf("approve host key: %v", err)
	}
	if status := store.TrustStatus(address, key); status != HostKeyTrustTrusted {
		t.Fatalf("approved trust status = %q, want trusted", status)
	}
	if err := store.Callback("192.0.2.65:22", nil, key); err != nil {
		t.Fatalf("reloaded callback rejected default-port host: %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) <= len("# managed trust\n") {
		t.Fatalf("known_hosts after approval = %q, error = %v", contents, err)
	}
}

func TestHostKeyStoreRejectsDifferentKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewHostKeyStore("known_hosts", path)
	if err != nil {
		t.Fatalf("create host-key store: %v", err)
	}
	address := "192.0.2.66:22"
	first := testHostKey(t)
	second := testHostKey(t)
	if err := store.Approve(address, first); err != nil {
		t.Fatalf("approve first host key: %v", err)
	}
	if status := store.TrustStatus(address, second); status != HostKeyTrustChanged {
		t.Fatalf("different trust status = %q, want changed", status)
	}
	if err := store.Approve(address, second); !errors.Is(err, ErrHostKeyConflict) {
		t.Fatalf("approve different key error = %v, want conflict", err)
	}
}

func TestProbeHostKeyStopsBeforeAuthentication(t *testing.T) {
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
	defer listener.Close()
	server := &ssh.ServerConfig{NoClientAuth: true}
	server.AddHostKey(signer)
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		_, _, _, err = ssh.NewServerConn(connection, server)
		serverDone <- err
	}()

	observation, err := ProbeHostKey(context.Background(), listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("probe host key: %v", err)
	}
	if observation.Key == nil || observation.Algorithm != ssh.KeyAlgoED25519 || observation.Fingerprint == "" || observation.AuthorizedKey == "" {
		t.Fatalf("observation = %+v", observation)
	}
	if want := ssh.FingerprintSHA256(signer.PublicKey()); observation.Fingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", observation.Fingerprint, want)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(observation.AuthorizedKey)); err != nil {
		t.Fatalf("authorized key = %q: %v", observation.AuthorizedKey, err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SSH probe server did not finish")
	}
}

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create host signer: %v", err)
	}
	return signer.PublicKey()
}
