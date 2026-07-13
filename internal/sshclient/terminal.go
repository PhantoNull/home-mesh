package sshclient

import (
	"context"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

type TerminalSession struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
}

func StartPasswordTerminal(address string, username string, password string, cols int, rows int, timeout time.Duration, hostKeyCallback ssh.HostKeyCallback) (*TerminalSession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return StartPasswordTerminalContext(ctx, address, username, password, cols, rows, timeout, hostKeyCallback)
}

func StartPasswordTerminalContext(ctx context.Context, address string, username string, password string, cols int, rows int, connectTimeout time.Duration, hostKeyCallback ssh.HostKeyCallback) (*TerminalSession, error) {
	setupCtx, cancelSetup := sshSetupContext(ctx, connectTimeout)
	defer cancelSetup()

	client, err := dialPassword(setupCtx, address, username, password, connectTimeout, hostKeyCallback)
	if err != nil {
		return nil, err
	}
	setupCancellation := closeClientOnCancellation(setupCtx, client)
	defer setupCancellation.Stop()

	session, err := client.NewSession()
	if err != nil {
		setupCancellation.Stop()
		_ = client.Close()
		return nil, fmt.Errorf("create ssh session: %w", preferContextError(setupCtx, err))
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		setupCancellation.Stop()
		_ = session.Close()
		_ = client.Close()
		return nil, fmt.Errorf("open ssh stdin: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		setupCancellation.Stop()
		_ = session.Close()
		_ = client.Close()
		return nil, fmt.Errorf("open ssh stdout: %w", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		setupCancellation.Stop()
		_ = session.Close()
		_ = client.Close()
		return nil, fmt.Errorf("open ssh stderr: %w", err)
	}

	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 36
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		setupCancellation.Stop()
		_ = session.Close()
		_ = client.Close()
		return nil, fmt.Errorf("request pty: %w", preferContextError(setupCtx, err))
	}

	if err := session.Shell(); err != nil {
		setupCancellation.Stop()
		_ = session.Close()
		_ = client.Close()
		return nil, fmt.Errorf("start shell: %w", preferContextError(setupCtx, err))
	}
	if err := finishSSHSetup(setupCtx, setupCancellation); err != nil {
		_ = session.Close()
		_ = client.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}

	return &TerminalSession{
		client:  client,
		session: session,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
	}, nil
}

func (s *TerminalSession) Stdout() io.Reader {
	return s.stdout
}

func (s *TerminalSession) Stderr() io.Reader {
	return s.stderr
}

func (s *TerminalSession) Write(data []byte) (int, error) {
	return s.stdin.Write(data)
}

func (s *TerminalSession) Resize(cols int, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	return s.session.WindowChange(rows, cols)
}

func (s *TerminalSession) Wait() error {
	return s.session.Wait()
}

func (s *TerminalSession) Close() error {
	if s.session != nil {
		_ = s.session.Close()
	}
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}
