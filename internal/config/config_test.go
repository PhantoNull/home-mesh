package config

import "testing"

func TestLoadAuthDisabledRequiresExplicitTrue(t *testing.T) {
	t.Setenv("HOME_MESH_AUTH_DISABLED", "true")
	if cfg := Load(); !cfg.AuthDisabled {
		t.Fatal("expected explicit true to disable authentication")
	}

	t.Setenv("HOME_MESH_AUTH_DISABLED", "invalid")
	if cfg := Load(); cfg.AuthDisabled {
		t.Fatal("invalid value must fail closed")
	}

	t.Setenv("HOME_MESH_AUTH_DISABLED", "")
	if cfg := Load(); cfg.AuthDisabled {
		t.Fatal("empty value must keep authentication enabled")
	}
}

func TestLoadUsesStrictSSHHostKeyVerificationByDefault(t *testing.T) {
	t.Setenv("HOME_MESH_ENV", "development")
	t.Setenv("HOME_MESH_SSH_HOST_KEY_MODE", "")

	if cfg := Load(); cfg.SSHHostKeyMode != "known_hosts" {
		t.Fatalf("SSH host key mode %q want known_hosts", cfg.SSHHostKeyMode)
	}
}
