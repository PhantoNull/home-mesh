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
	"golang.org/x/crypto/ssh/knownhosts"
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

	client, err := dialPasswordAttempt(ctx, address, username, password, connectTimeout, hostKeyCallback, nil)
	if err == nil {
		return client, nil
	}

	// A server can prefer an unpinned key type even when another key for the
	// same host is pinned. Retry once using only algorithms derived from those
	// pinned keys; SSH does not send authentication before host verification.
	trustedAlgorithms := trustedHostKeyAlgorithms(err)
	if len(trustedAlgorithms) == 0 {
		return nil, err
	}
	client, retryErr := dialPasswordAttempt(ctx, address, username, password, connectTimeout, hostKeyCallback, trustedAlgorithms)
	if retryErr == nil {
		return client, nil
	}
	if ctx.Err() != nil {
		return nil, retryErr
	}
	var negotiationErr *ssh.AlgorithmNegotiationError
	if errors.As(retryErr, &negotiationErr) {
		return nil, err
	}
	return nil, retryErr
}

func dialPasswordAttempt(ctx context.Context, address string, username string, password string, connectTimeout time.Duration, hostKeyCallback ssh.HostKeyCallback, hostKeyAlgorithms []string) (*ssh.Client, error) {
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
		if ctx.Err() != nil {
			return nil, fmt.Errorf("connect ssh: %w", ctx.Err())
		}
		return nil, fmt.Errorf("set ssh handshake deadline: %w", err)
	}

	config := &ssh.ClientConfig{
		User:              username,
		HostKeyAlgorithms: hostKeyAlgorithms,
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

func trustedHostKeyAlgorithms(err error) []string {
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) || len(keyErr.Want) == 0 {
		return nil
	}

	supported := make(map[string]struct{})
	for _, algorithm := range ssh.SupportedAlgorithms().HostKeys {
		supported[algorithm] = struct{}{}
	}
	algorithms := make([]string, 0, len(keyErr.Want))
	seen := make(map[string]struct{})
	appendSupported := func(candidates ...string) {
		for _, candidate := range candidates {
			if _, ok := supported[candidate]; !ok {
				continue
			}
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			algorithms = append(algorithms, candidate)
		}
	}

	for _, knownKey := range keyErr.Want {
		if knownKey.Key == nil {
			continue
		}
		switch knownKey.Key.Type() {
		case ssh.KeyAlgoRSA:
			appendSupported(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
		case ssh.CertAlgoRSAv01:
			appendSupported(ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01)
		default:
			appendSupported(knownKey.Key.Type())
		}
	}
	return algorithms
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
