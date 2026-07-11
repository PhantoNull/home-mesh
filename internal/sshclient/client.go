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

const (
	DefaultMaxCommandOutput = 1 << 20
	defaultConnectTimeout   = 10 * time.Second
)

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
	setupCtx, cancelSetup := sshSetupContext(ctx, connectTimeout)
	defer cancelSetup()

	client, err := dialPassword(setupCtx, address, username, password, connectTimeout, hostKeyCallback)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = client.Close() }()
	setupCancellation := closeClientOnCancellation(setupCtx, client)
	defer setupCancellation.Stop()

	session, err := client.NewSession()
	if err != nil {
		setupCancellation.Stop()
		return Result{}, fmt.Errorf("create ssh session: %w", preferContextError(setupCtx, err))
	}
	defer func() { _ = session.Close() }()

	output := newBoundedOutput(maxOutputBytes)
	session.Stdout = output
	session.Stderr = output

	if err := session.Start(command); err != nil {
		setupCancellation.Stop()
		return Result{}, fmt.Errorf("start ssh command: %w", preferContextError(setupCtx, err))
	}
	if err := finishSSHSetup(setupCtx, setupCancellation); err != nil {
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
		connectTimeout = defaultConnectTimeout
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
	deadlineFromContext := false
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
		deadlineFromContext = true
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
		var timeoutError net.Error
		if deadlineFromContext && errors.As(err, &timeoutError) && timeoutError.Timeout() {
			return nil, fmt.Errorf("connect ssh: %w", context.DeadlineExceeded)
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

func sshSetupContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = defaultConnectTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

type sshSetupCancellation struct {
	stop        func() bool
	done        chan struct{}
	stopOnce    sync.Once
	stoppedIdle bool
}

func closeClientOnCancellation(ctx context.Context, client *ssh.Client) *sshSetupCancellation {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = client.Close()
	})
	return &sshSetupCancellation{stop: stop, done: done}
}

// Stop prevents the cancellation callback or waits until an in-flight callback
// has finished closing the client. It is safe to call more than once.
func (c *sshSetupCancellation) Stop() bool {
	c.stopOnce.Do(func() {
		c.stoppedIdle = c.stop()
		if !c.stoppedIdle {
			<-c.done
		}
	})
	return c.stoppedIdle
}

func finishSSHSetup(ctx context.Context, cancellation *sshSetupCancellation) error {
	stopped := cancellation.Stop()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !stopped {
		return context.Canceled
	}
	return nil
}

func preferContextError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
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
