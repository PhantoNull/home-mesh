package sshclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestDialPasswordRetriesAHostKeyAlgorithmAlreadyInKnownHosts(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA host key: %v", err)
	}
	ecdsaSigner, err := ssh.NewSignerFromKey(ecdsaKey)
	if err != nil {
		t.Fatalf("create ECDSA host signer: %v", err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ED25519 host key: %v", err)
	}
	ed25519Signer, err := ssh.NewSignerFromKey(ed25519Key)
	if err != nil {
		t.Fatalf("create ED25519 host signer: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var passwordChecks atomic.Int32
	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			passwordChecks.Add(1)
			if string(password) != "password" {
				return nil, errors.New("invalid password")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(ecdsaSigner)
	serverConfig.AddHostKey(ed25519Signer)
	go serveSSHHandshakes(listener, serverConfig)

	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	trustedLine := knownhosts.Line(
		[]string{knownhosts.Normalize(listener.Addr().String())},
		ed25519Signer.PublicKey(),
	)
	if err := os.WriteFile(knownHostsPath, []byte(trustedLine+"\n"), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	knownHostsCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		t.Fatalf("load known_hosts: %v", err)
	}

	var seenMu sync.Mutex
	seenAlgorithms := make([]string, 0, 2)
	callback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		seenMu.Lock()
		seenAlgorithms = append(seenAlgorithms, key.Type())
		seenMu.Unlock()
		return knownHostsCallback(hostname, remote, key)
	}

	client, err := dialPassword(context.Background(), listener.Addr().String(), "user", "password", time.Second, callback)
	if err != nil {
		t.Fatalf("dial using trusted alternate host key: %v", err)
	}
	_ = client.Close()

	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seenAlgorithms) != 2 || seenAlgorithms[0] != ssh.KeyAlgoECDSA256 || seenAlgorithms[1] != ssh.KeyAlgoED25519 {
		t.Fatalf("host key algorithms = %v, want [%s %s]", seenAlgorithms, ssh.KeyAlgoECDSA256, ssh.KeyAlgoED25519)
	}
	if passwordChecks.Load() != 1 {
		t.Fatalf("password authentication attempts = %d, want 1 after the trusted host key was selected", passwordChecks.Load())
	}
}

func TestTrustedHostKeyAlgorithmsDoesNotRetryUnknownOrUnusableTrust(t *testing.T) {
	for name, err := range map[string]error{
		"unknown host":    &knownhosts.KeyError{},
		"nil key":         &knownhosts.KeyError{Want: []knownhosts.KnownKey{{}}},
		"unrelated error": errors.New("host key callback failed"),
	} {
		t.Run(name, func(t *testing.T) {
			if algorithms := trustedHostKeyAlgorithms(err); len(algorithms) != 0 {
				t.Fatalf("trusted algorithms = %v, want none", algorithms)
			}
		})
	}
}

func serveSSHHandshakes(listener net.Listener, config *ssh.ServerConfig) {
	for {
		rawConnection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			connection, channels, requests, err := ssh.NewServerConn(rawConnection, config)
			if err != nil {
				_ = rawConnection.Close()
				return
			}
			go ssh.DiscardRequests(requests)
			go func() {
				for channel := range channels {
					_ = channel.Reject(ssh.UnknownChannelType, "test server does not accept channels")
				}
			}()
			_ = connection.Wait()
		}()
	}
}

func TestDialPasswordBoundsStalledHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = dialPassword(ctx, listener.Addr().String(), "user", "password", time.Second, ssh.InsecureIgnoreHostKey())
	if err == nil {
		t.Fatal("expected stalled handshake to fail")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("handshake deadline was not enforced: %s", elapsed)
	}

	select {
	case connection := <-accepted:
		_ = connection.Close()
	case <-time.After(time.Second):
		t.Fatal("server did not accept test connection")
	}
}

func TestDialPasswordCancellationInterruptsStalledHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, dialErr := dialPassword(ctx, listener.Addr().String(), "user", "password", 5*time.Second, ssh.InsecureIgnoreHostKey())
		result <- dialErr
	}()

	select {
	case connection := <-accepted:
		defer connection.Close()
	case <-time.After(time.Second):
		t.Fatal("server did not accept test connection")
	}
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt SSH handshake")
	}
}

func TestBoundedOutputConsumesAndTruncates(t *testing.T) {
	output := newBoundedOutput(5)

	written, err := output.Write([]byte("123456789"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if written != 9 {
		t.Fatalf("reported write %d want 9", written)
	}

	result := output.result()
	if result.Output != "12345" {
		t.Fatalf("output %q want %q", result.Output, "12345")
	}
	if !result.Truncated {
		t.Fatal("expected truncation flag")
	}
}
