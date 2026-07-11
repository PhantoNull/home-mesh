package sshclient

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var ErrHostKeyTrustUnavailable = errors.New("SSH host-key trust unavailable")

func HostKeyCallback(mode string, knownHostsPath string) (ssh.HostKeyCallback, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "known_hosts":
		if strings.TrimSpace(knownHostsPath) == "" {
			return nil, fmt.Errorf("%w: known_hosts path is required", ErrHostKeyTrustUnavailable)
		}
		info, err := os.Lstat(knownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("%w: open known_hosts file: %v", ErrHostKeyTrustUnavailable, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: known_hosts file must not be a symbolic link", ErrHostKeyTrustUnavailable)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: known_hosts path must be a regular file", ErrHostKeyTrustUnavailable)
		}
		if err := validateKnownHostsPermissions(info); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHostKeyTrustUnavailable, err)
		}
		callback, err := knownhosts.New(knownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("%w: load known_hosts: %v", ErrHostKeyTrustUnavailable, err)
		}
		return callback, nil
	default:
		return nil, fmt.Errorf("unsupported ssh host key mode %q", mode)
	}
}
