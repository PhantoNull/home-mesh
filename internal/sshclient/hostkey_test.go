package sshclient

import "testing"

func TestHostKeyCallbackModes(t *testing.T) {
	t.Parallel()

	if _, err := HostKeyCallback("insecure", ""); err == nil {
		t.Fatal("insecure mode must be rejected")
	}

	if _, err := HostKeyCallback("known_hosts", ""); err == nil {
		t.Fatal("known_hosts mode without a path should fail")
	}
}
