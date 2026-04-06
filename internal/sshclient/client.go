package sshclient

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Result struct {
	Output string
}

func RunPasswordCommand(address string, username string, password string, command string, timeout time.Duration, hostKeyCallback ssh.HostKeyCallback) (Result, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}

	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return Result{}, fmt.Errorf("connect ssh: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("create ssh session: %w", err)
	}
	defer session.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(command); err != nil {
		combined := strings.TrimSpace(strings.Join([]string{stdout.String(), stderr.String()}, "\n"))
		if combined == "" {
			return Result{}, fmt.Errorf("run ssh command: %w", err)
		}
		return Result{Output: combined}, fmt.Errorf("run ssh command: %w", err)
	}

	output := strings.TrimSpace(strings.Join([]string{stdout.String(), stderr.String()}, "\n"))
	return Result{Output: output}, nil
}
