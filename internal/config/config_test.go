package config

import "testing"

func TestLoadUsesHomeMeshAPIListenPortByDefault(t *testing.T) {
	t.Setenv("HOME_MESH_HTTP_ADDR", "")

	if cfg := mustLoad(t); cfg.HTTPAddr != ":18080" {
		t.Fatalf("HTTP address %q want :18080", cfg.HTTPAddr)
	}
}

func TestLoadAuthDisabledRequiresExplicitTrue(t *testing.T) {
	t.Setenv("HOME_MESH_AUTH_DISABLED", "true")
	if cfg := mustLoad(t); !cfg.AuthDisabled {
		t.Fatal("expected explicit true to disable authentication")
	}

	t.Setenv("HOME_MESH_AUTH_DISABLED", "invalid")
	if _, err := Load(); err == nil {
		t.Fatal("invalid value must be rejected")
	}

	t.Setenv("HOME_MESH_AUTH_DISABLED", "")
	if cfg := mustLoad(t); cfg.AuthDisabled {
		t.Fatal("empty value must keep authentication enabled")
	}
}

func TestLoadUsesStrictSSHHostKeyVerificationByDefault(t *testing.T) {
	t.Setenv("HOME_MESH_ENV", "development")
	t.Setenv("HOME_MESH_SSH_HOST_KEY_MODE", "")

	if cfg := mustLoad(t); cfg.SSHHostKeyMode != "known_hosts" {
		t.Fatalf("SSH host key mode %q want known_hosts", cfg.SSHHostKeyMode)
	}
}

func TestLoadTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("HOME_MESH_TRUSTED_PROXY_CIDRS", " 172.16.0.0/12, 2001:db8::/32 ,, ")

	cfg := mustLoad(t)
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("got %v want two trusted proxy CIDRs", cfg.TrustedProxyCIDRs)
	}
	if cfg.TrustedProxyCIDRs[0] != "172.16.0.0/12" || cfg.TrustedProxyCIDRs[1] != "2001:db8::/32" {
		t.Fatalf("unexpected trusted proxy CIDRs: %v", cfg.TrustedProxyCIDRs)
	}
}

func TestLoadDiscoveryPublicNetworksRequireExplicitOptIn(t *testing.T) {
	t.Setenv("HOME_MESH_DISCOVERY_ALLOW_PUBLIC", "true")
	if cfg := mustLoad(t); !cfg.DiscoveryAllowPublic {
		t.Fatal("expected explicit public discovery opt-in")
	}

	t.Setenv("HOME_MESH_DISCOVERY_ALLOW_PUBLIC", "invalid")
	if _, err := Load(); err == nil {
		t.Fatal("invalid public discovery value must be rejected")
	}
}

func TestLoadDemoDataRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("HOME_MESH_SEED_DEMO_DATA", "true")
	if cfg := mustLoad(t); !cfg.SeedDemoData {
		t.Fatal("expected explicit demo seed opt-in")
	}

	t.Setenv("HOME_MESH_SEED_DEMO_DATA", "invalid")
	if _, err := Load(); err == nil {
		t.Fatal("invalid demo seed value must be rejected")
	}
}

func TestLoadRejectsInvalidOperationalValues(t *testing.T) {
	t.Setenv("HOME_MESH_SCAN_INTERVAL", "2s")
	if _, err := Load(); err == nil {
		t.Fatal("expected short scan interval to be rejected")
	}

	t.Setenv("HOME_MESH_SCAN_INTERVAL", "30s")
	t.Setenv("HOME_MESH_TRUSTED_PROXY_CIDRS", "not-a-cidr")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid trusted proxy CIDR to be rejected")
	}

	t.Setenv("HOME_MESH_TRUSTED_PROXY_CIDRS", "")
	t.Setenv("HOME_MESH_SESSION_DURATION", "25h")
	if _, err := Load(); err == nil {
		t.Fatal("expected excessive session duration to be rejected")
	}
}

func TestLoadParsesMasterKeyVersions(t *testing.T) {
	t.Setenv("HOME_MESH_MASTER_KEY", "current-key")
	t.Setenv("HOME_MESH_MASTER_KEY_VERSION", "3")
	t.Setenv("HOME_MESH_PREVIOUS_MASTER_KEYS", "1:first-key,2:second-key")

	cfg := mustLoad(t)
	if cfg.MasterKeyVersion != 3 {
		t.Fatalf("master key version %d want 3", cfg.MasterKeyVersion)
	}
	if cfg.PreviousMasterKeys[1] != "first-key" || cfg.PreviousMasterKeys[2] != "second-key" {
		t.Fatalf("unexpected previous keys: %v", cfg.PreviousMasterKeys)
	}
}

func mustLoad(t *testing.T) Config {
	t.Helper()
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	return cfg
}
