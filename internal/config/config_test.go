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

func TestLoadTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("HOME_MESH_TRUSTED_PROXY_CIDRS", " 172.16.0.0/12, 2001:db8::/32 ,, ")

	cfg := Load()
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("got %v want two trusted proxy CIDRs", cfg.TrustedProxyCIDRs)
	}
	if cfg.TrustedProxyCIDRs[0] != "172.16.0.0/12" || cfg.TrustedProxyCIDRs[1] != "2001:db8::/32" {
		t.Fatalf("unexpected trusted proxy CIDRs: %v", cfg.TrustedProxyCIDRs)
	}
}

func TestLoadDiscoveryPublicNetworksRequireExplicitOptIn(t *testing.T) {
	t.Setenv("HOME_MESH_DISCOVERY_ALLOW_PUBLIC", "true")
	if cfg := Load(); !cfg.DiscoveryAllowPublic {
		t.Fatal("expected explicit public discovery opt-in")
	}

	t.Setenv("HOME_MESH_DISCOVERY_ALLOW_PUBLIC", "invalid")
	if cfg := Load(); cfg.DiscoveryAllowPublic {
		t.Fatal("invalid public discovery value must fail closed")
	}
}
