package sshclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const DefaultMaxCommandOutput = 1 << 20

type Result struct {
	Output    string
	Truncated bool
}

func RunPasswordCommand(address string, username string, password string, command string, timeout time.Duration, hostKeyCallback ssh.HostKeyCallback) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return RunPasswordCommandContext(ctx, address, username, password, command, timeout, DefaultMaxCommandOutput, hostKeyCallback)
}

func RunPasswordCommandContext(ctx context.Context, address string, username string, password string, command string, connectTimeout time.Duration, maxOutputBytes int, hostKeyCallback ssh.HostKeyCallback) (Result, error) {
	client, err := dialPassword(ctx, address, username, password, connectTimeout, hostKeyCallback)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("create ssh session: %w", err)
	}
	defer func() { _ = session.Close() }()

	output := newBoundedOutput(maxOutputBytes)
	session.Stdout = output
	session.Stderr = output

	if err := session.Start(command); err != nil {
		return Result{}, fmt.Errorf("start ssh command: %w", err)
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- session.Wait()
	}()

	select {
	case err := <-waitDone:
		result := output.result()
		if err != nil {
			return result, fmt.Errorf("run ssh command: %w", err)
		}
		return result, nil
	case <-ctx.Done():
		_ = session.Close()
		_ = client.Close()
		<-waitDone
		return output.result(), fmt.Errorf("run ssh command: %w", ctx.Err())
	}
}

func dialPassword(ctx context.Context, address string, username string, password string, connectTimeout time.Duration, hostKeyCallback ssh.HostKeyCallback) (*ssh.Client, error) {
	if hostKeyCallback == nil {
		return nil, errors.New("connect ssh: host key callback is required")
	}
	if connectTimeout <= 0 {
		connectTimeout = 10 * time.Second
	}

	dialer := net.Dialer{Timeout: connectTimeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect ssh: %w", err)
	}
	stopCloseOnCancel := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})

	deadline := time.Now().Add(connectTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		stopCloseOnCancel()
		_ = connection.Close()
		return nil, fmt.Errorf("set ssh handshake deadline: %w", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: hostKeyCallback,
	}

	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, config)
	closeOnCancelStopped := stopCloseOnCancel()
	if err != nil {
		_ = connection.Close()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("connect ssh: %w", ctx.Err())
		}
		return nil, fmt.Errorf("connect ssh: %w", err)
	}
	if !closeOnCancelStopped || ctx.Err() != nil {
		_ = clientConnection.Close()
		return nil, fmt.Errorf("connect ssh: %w", ctx.Err())
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		_ = clientConnection.Close()
		return nil, fmt.Errorf("clear ssh handshake deadline: %w", err)
	}

	return ssh.NewClient(clientConnection, channels, requests), nil
}

type boundedOutput struct {
	mu        sync.Mutex
	data      []byte
	limit     int
	truncated bool
}

func newBoundedOutput(limit int) *boundedOutput {
	if limit <= 0 {
		limit = DefaultMaxCommandOutput
	}
	return &boundedOutput{limit: limit, data: make([]byte, 0, min(limit, 4096))}
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	remaining := b.limit - len(b.data)
	if remaining > 0 {
		toCopy := len(data)
		if toCopy > remaining {
			toCopy = remaining
		}
		b.data = append(b.data, data[:toCopy]...)
	}
	if len(data) > remaining {
		b.truncated = true
	}
	return len(data), nil
}

func (b *boundedOutput) result() Result {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Result{Output: strings.TrimSpace(string(b.data)), Truncated: b.truncated}
}
