package sshclient

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHostKeyCallbackModes(t *testing.T) {
	t.Parallel()

	if _, err := HostKeyCallback("insecure", ""); err == nil {
		t.Fatal("insecure mode must be rejected")
	}

	if _, err := HostKeyCallback("known_hosts", ""); err == nil {
		t.Fatal("known_hosts mode without a path should fail")
	} else if !errors.Is(err, ErrHostKeyTrustUnavailable) {
		t.Fatalf("missing known_hosts error = %v", err)
	}
}

func TestHostKeyCallbackAcceptsProtectedRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HostKeyCallback("known_hosts", path); err != nil {
		t.Fatalf("protected known_hosts file: %v", err)
	}
}

func TestHostKeyCallbackRejectsNonRegularAndWritableFiles(t *testing.T) {
	directory := t.TempDir()
	if _, err := HostKeyCallback("known_hosts", directory); err == nil {
		t.Fatal("known_hosts directory was accepted")
	}

	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err == nil {
		if _, err := HostKeyCallback("known_hosts", link); err == nil {
			t.Fatal("known_hosts symlink was accepted")
		}
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(target, 0o622); err != nil {
			t.Fatal(err)
		}
		if _, err := HostKeyCallback("known_hosts", target); err == nil {
			t.Fatal("group/world-writable known_hosts file was accepted")
		}
	}
}
