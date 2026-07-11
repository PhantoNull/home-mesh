package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshStallPoint string

const (
	stallChannelOpen sshStallPoint = "channel-open"
	stallPTYRequest  sshStallPoint = "pty-request"
	stallShell       sshStallPoint = "shell"
	stallExec        sshStallPoint = "exec"
)

func TestPostHandshakeSetupObservesCancellation(t *testing.T) {
	tests := []struct {
		name       string
		stallPoint sshStallPoint
		start      func(context.Context, string) error
	}{
		{
			name:       "command new session",
			stallPoint: stallChannelOpen,
			start: func(ctx context.Context, address string) error {
				_, err := RunPasswordCommandContext(ctx, address, "user", "password", "true", 5*time.Second, 1024, ssh.InsecureIgnoreHostKey())
				return err
			},
		},
		{
			name:       "command start",
			stallPoint: stallExec,
			start: func(ctx context.Context, address string) error {
				_, err := RunPasswordCommandContext(ctx, address, "user", "password", "true", 5*time.Second, 1024, ssh.InsecureIgnoreHostKey())
				return err
			},
		},
		{
			name:       "terminal new session",
			stallPoint: stallChannelOpen,
			start: func(ctx context.Context, address string) error {
				session, err := StartPasswordTerminalContext(ctx, address, "user", "password", 80, 24, 5*time.Second, ssh.InsecureIgnoreHostKey())
				if session != nil {
					_ = session.Close()
				}
				return err
			},
		},
		{
			name:       "terminal pty request",
			stallPoint: stallPTYRequest,
			start: func(ctx context.Context, address string) error {
				session, err := StartPasswordTerminalContext(ctx, address, "user", "password", 80, 24, 5*time.Second, ssh.InsecureIgnoreHostKey())
				if session != nil {
					_ = session.Close()
				}
				return err
			},
		},
		{
			name:       "terminal shell",
			stallPoint: stallShell,
			start: func(ctx context.Context, address string) error {
				session, err := StartPasswordTerminalContext(ctx, address, "user", "password", 80, 24, 5*time.Second, ssh.InsecureIgnoreHostKey())
				if session != nil {
					_ = session.Close()
				}
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			peer := newStalledSSHPeer(t, test.stallPoint)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				result <- test.start(ctx, peer.address())
			}()

			peer.awaitStall(t)
			cancel()

			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("setup error = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("post-handshake setup did not stop after cancellation")
			}
		})
	}
}

func TestPostHandshakeSetupHonorsConnectTimeout(t *testing.T) {
	peer := newStalledSSHPeer(t, stallShell)
	result := make(chan error, 1)
	go func() {
		session, err := StartPasswordTerminalContext(
			context.Background(),
			peer.address(),
			"user",
			"password",
			80,
			24,
			time.Second,
			ssh.InsecureIgnoreHostKey(),
		)
		if session != nil {
			_ = session.Close()
		}
		result <- err
	}()

	peer.awaitStall(t)
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("setup error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("post-handshake setup exceeded its connect timeout")
	}
}

type stalledSSHPeer struct {
	listener net.Listener
	point    sshStallPoint
	config   *ssh.ServerConfig

	stalled chan struct{}
	release chan struct{}
	done    chan struct{}
	err     chan error

	closeOnce sync.Once
	connMu    sync.Mutex
	conn      net.Conn
}

func newStalledSSHPeer(t *testing.T, point sshStallPoint) *stalledSSHPeer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate SSH host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create SSH host signer: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for stalled SSH peer: %v", err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	peer := &stalledSSHPeer{
		listener: listener,
		point:    point,
		config:   config,
		stalled:  make(chan struct{}),
		release:  make(chan struct{}),
		done:     make(chan struct{}),
		err:      make(chan error, 1),
	}
	go peer.serve()
	t.Cleanup(peer.close)
	return peer
}

func (p *stalledSSHPeer) address() string {
	return p.listener.Addr().String()
}

func (p *stalledSSHPeer) serve() {
	defer close(p.done)
	rawConnection, err := p.listener.Accept()
	if err != nil {
		p.reportError(fmt.Errorf("accept SSH client: %w", err))
		return
	}
	p.connMu.Lock()
	p.conn = rawConnection
	p.connMu.Unlock()

	connection, channels, requests, err := ssh.NewServerConn(rawConnection, p.config)
	if err != nil {
		p.reportError(fmt.Errorf("complete SSH handshake: %w", err))
		return
	}
	defer connection.Close()
	go ssh.DiscardRequests(requests)

	newChannel, ok := <-channels
	if !ok {
		p.reportError(errors.New("SSH client closed before opening a session channel"))
		return
	}
	if p.point == stallChannelOpen {
		close(p.stalled)
		<-p.release
		_ = newChannel.Reject(ssh.ConnectionFailed, "test released stalled channel")
		return
	}

	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		p.reportError(fmt.Errorf("accept SSH session channel: %w", err))
		return
	}
	defer channel.Close()
	for request := range channelRequests {
		if request.Type == string(p.point) || (p.point == stallPTYRequest && request.Type == "pty-req") {
			close(p.stalled)
			<-p.release
			_ = request.Reply(false, nil)
			return
		}
		switch request.Type {
		case "pty-req":
			_ = request.Reply(true, nil)
		default:
			_ = request.Reply(false, nil)
		}
	}
	p.reportError(fmt.Errorf("SSH channel closed before reaching stall point %q", p.point))
}

func (p *stalledSSHPeer) awaitStall(t *testing.T) {
	t.Helper()
	select {
	case <-p.stalled:
	case err := <-p.err:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatalf("SSH peer did not reach stall point %q", p.point)
	}
}

func (p *stalledSSHPeer) reportError(err error) {
	select {
	case p.err <- err:
	default:
	}
}

func (p *stalledSSHPeer) close() {
	p.closeOnce.Do(func() {
		close(p.release)
		_ = p.listener.Close()
		p.connMu.Lock()
		if p.conn != nil {
			_ = p.conn.Close()
		}
		p.connMu.Unlock()
		select {
		case <-p.done:
		case <-time.After(time.Second):
		}
	})
}
