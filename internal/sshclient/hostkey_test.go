package sshclient

import "testing"

func TestHostKeyCallbackModes(t *testing.T) {
	t.Parallel()

	if _, err := HostKeyCallback("insecure", ""); err != nil {
		t.Fatalf("insecure mode should succeed: %v", err)
	}

	if _, err := HostKeyCallback("known_hosts", ""); err == nil {
		t.Fatal("known_hosts mode without a path should fail")
	}
}
