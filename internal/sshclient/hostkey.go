package sshclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var ErrHostKeyTrustUnavailable = errors.New("SSH host-key trust unavailable")
var ErrHostKeyCapture = errors.New("SSH host key captured")
var ErrHostKeyConflict = errors.New("SSH host key conflicts with an existing trusted key")

const (
	defaultHostKeyProbeTimeout = 10 * time.Second
	HostKeyTrustUnknown        = "unknown"
	HostKeyTrustTrusted        = "trusted"
	HostKeyTrustChanged        = "changed"
)

// HostKeyObservation is the public identity of an SSH host key returned by a
// probe. The key is carried in memory for the immediate approval comparison and
// is never serialized by the API.
type HostKeyObservation struct {
	Key           ssh.PublicKey
	Algorithm     string
	Fingerprint   string
	AuthorizedKey string
}

// HostKeyStore owns the process-local known_hosts callback and reloads it when
// a host key is explicitly approved. The file is expected to be persistent in
// the deployment (the Docker entrypoint uses /data/known_hosts).
type HostKeyStore struct {
	mu       sync.RWMutex
	path     string
	callback ssh.HostKeyCallback
}

func NewHostKeyStore(mode string, knownHostsPath string) (*HostKeyStore, error) {
	callback, err := HostKeyCallback(mode, knownHostsPath)
	if err != nil {
		return nil, err
	}
	return &HostKeyStore{path: knownHostsPath, callback: callback}, nil
}

func (s *HostKeyStore) Callback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	s.mu.RLock()
	callback := s.callback
	s.mu.RUnlock()
	if callback == nil {
		return fmt.Errorf("%w: callback is unavailable", ErrHostKeyTrustUnavailable)
	}
	if remote == nil {
		remote = hostKeyRemoteAddress(hostname)
	}
	return callback(hostname, remote, key)
}

func (s *HostKeyStore) TrustStatus(hostname string, key ssh.PublicKey) string {
	s.mu.RLock()
	callback := s.callback
	s.mu.RUnlock()
	return classifyHostKey(callback, hostname, key)
}

// Approve adds an unknown algorithm key without replacing a different key of
// the same algorithm already pinned for the host. It reloads the callback
// before returning.
func (s *HostKeyStore) Approve(hostname string, key ssh.PublicKey) error {
	if s == nil || key == nil {
		return fmt.Errorf("%w: host key is missing", ErrHostKeyTrustUnavailable)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.callback == nil || strings.TrimSpace(s.path) == "" {
		return fmt.Errorf("%w: callback or path is unavailable", ErrHostKeyTrustUnavailable)
	}

	switch classifyHostKey(s.callback, hostname, key) {
	case HostKeyTrustTrusted:
		return nil
	case HostKeyTrustChanged:
		return ErrHostKeyConflict
	}

	contents, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read known_hosts before approval: %w", err)
	}
	host := knownhosts.Normalize(hostname)
	line := fmt.Sprintf("%s %s\n", host, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	if !strings.HasSuffix(string(contents), "\n") && len(contents) > 0 {
		contents = append(contents, '\n')
	}
	contents = append(contents, []byte(line)...)
	if err := writeKnownHostsAtomically(s.path, contents); err != nil {
		return err
	}

	callback, err := HostKeyCallback("known_hosts", s.path)
	if err != nil {
		return fmt.Errorf("reload known_hosts after approval: %w", err)
	}
	s.callback = callback
	return nil
}

func classifyHostKey(callback ssh.HostKeyCallback, hostname string, key ssh.PublicKey) string {
	if callback == nil || key == nil {
		return HostKeyTrustUnknown
	}
	if err := callback(hostname, hostKeyRemoteAddress(hostname), key); err == nil {
		return HostKeyTrustTrusted
	} else {
		var revokedErr *knownhosts.RevokedError
		if errors.As(err, &revokedErr) {
			return HostKeyTrustChanged
		}
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) && len(keyErr.Want) > 0 {
			// A host can legitimately publish several key algorithms. A
			// different algorithm is an additional key to enroll; a mismatch
			// for the same algorithm is a rotation/conflict and must be reviewed.
			for _, knownKey := range keyErr.Want {
				if knownKey.Key != nil && knownKey.Key.Type() == key.Type() {
					return HostKeyTrustChanged
				}
			}
			return HostKeyTrustUnknown
		}
	}
	return HostKeyTrustUnknown
}

type hostKeyAddr string

func (a hostKeyAddr) Network() string { return "tcp" }
func (a hostKeyAddr) String() string  { return string(a) }

func hostKeyRemoteAddress(hostname string) net.Addr {
	if _, _, err := net.SplitHostPort(hostname); err == nil {
		return hostKeyAddr(hostname)
	}
	return hostKeyAddr(net.JoinHostPort(hostname, "22"))
}

func writeKnownHostsAtomically(path string, contents []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".known_hosts-*")
	if err != nil {
		return fmt.Errorf("create known_hosts replacement: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect known_hosts replacement: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write known_hosts replacement: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync known_hosts replacement: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close known_hosts replacement: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace known_hosts: %w", err)
	}
	return nil
}

// ProbeHostKey completes only the SSH host-key exchange. It never sends a
// password and returns the observed key before authentication is attempted.
func ProbeHostKey(ctx context.Context, address string, timeout time.Duration) (HostKeyObservation, error) {
	if strings.TrimSpace(address) == "" {
		return HostKeyObservation{}, errors.New("SSH host address is required")
	}
	if timeout <= 0 {
		timeout = defaultHostKeyProbeTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(probeCtx, "tcp", address)
	if err != nil {
		return HostKeyObservation{}, fmt.Errorf("probe SSH host key: %w", err)
	}
	defer connection.Close()
	if deadline, ok := probeCtx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return HostKeyObservation{}, fmt.Errorf("set SSH host-key probe deadline: %w", err)
		}
	}

	var observed HostKeyObservation
	config := &ssh.ClientConfig{
		User: "home-mesh-host-key-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			observed = describeHostKey(key)
			return ErrHostKeyCapture
		},
	}
	_, _, _, handshakeErr := ssh.NewClientConn(connection, address, config)
	if observed.Key != nil {
		return observed, nil
	}
	if probeCtx.Err() != nil {
		return HostKeyObservation{}, fmt.Errorf("probe SSH host key: %w", probeCtx.Err())
	}
	if handshakeErr != nil {
		return HostKeyObservation{}, fmt.Errorf("probe SSH host key: %w", handshakeErr)
	}
	return HostKeyObservation{}, errors.New("probe SSH host key: server did not present a host key")
}

func describeHostKey(key ssh.PublicKey) HostKeyObservation {
	return HostKeyObservation{
		Key:           key,
		Algorithm:     key.Type(),
		Fingerprint:   ssh.FingerprintSHA256(key),
		AuthorizedKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
	}
}

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
