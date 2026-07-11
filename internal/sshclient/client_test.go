package sshclient

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

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
