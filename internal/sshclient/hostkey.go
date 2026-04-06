package sshclient

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func HostKeyCallback(mode string, knownHostsPath string) (ssh.HostKeyCallback, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "known_hosts":
		if strings.TrimSpace(knownHostsPath) == "" {
			return nil, fmt.Errorf("known_hosts path is required when ssh host key mode is known_hosts")
		}
		if _, err := os.Stat(knownHostsPath); err != nil {
			return nil, fmt.Errorf("open known_hosts file: %w", err)
		}
		callback, err := knownhosts.New(knownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("load known_hosts: %w", err)
		}
		return callback, nil
	case "insecure":
		return ssh.InsecureIgnoreHostKey(), nil
	default:
		return nil, fmt.Errorf("unsupported ssh host key mode %q", mode)
	}
}
