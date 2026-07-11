package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr               string
	AppName                string
	Env                    string
	DBPath                 string
	NmapPath               string
	DiscoveryAllowPublic   bool
	SeedDemoData           bool
	MasterKeyBase          string
	MasterKeyVersion       int
	PreviousMasterKeys     map[int]string
	SSHHostKeyMode         string
	KnownHostsPath         string
	SessionSecret          string
	AuthDisabled           bool
	TrustedProxyCIDRs      []string
	BootstrapAdminUsername string
	BootstrapAdminPassword string
	ScanInterval           time.Duration
}

func Load() (Config, error) {
	authDisabled, err := parseBool("HOME_MESH_AUTH_DISABLED", false)
	if err != nil {
		return Config{}, err
	}
	discoveryAllowPublic, err := parseBool("HOME_MESH_DISCOVERY_ALLOW_PUBLIC", false)
	if err != nil {
		return Config{}, err
	}
	seedDemoData, err := parseBool("HOME_MESH_SEED_DEMO_DATA", false)
	if err != nil {
		return Config{}, err
	}
	scanInterval, err := parseDuration(getEnv("HOME_MESH_SCAN_INTERVAL", "30s"))
	if err != nil {
		return Config{}, fmt.Errorf("HOME_MESH_SCAN_INTERVAL: %w", err)
	}
	trustedProxyCIDRs := commaSeparatedValues(os.Getenv("HOME_MESH_TRUSTED_PROXY_CIDRS"))
	for _, value := range trustedProxyCIDRs {
		if _, err := netip.ParsePrefix(value); err != nil {
			return Config{}, fmt.Errorf("HOME_MESH_TRUSTED_PROXY_CIDRS entry %q: %w", value, err)
		}
	}
	masterKeyVersion, err := parsePositiveInt("HOME_MESH_MASTER_KEY_VERSION", 2)
	if err != nil {
		return Config{}, err
	}
	previousMasterKeys, err := parseVersionedKeys(os.Getenv("HOME_MESH_PREVIOUS_MASTER_KEYS"))
	if err != nil {
		return Config{}, fmt.Errorf("HOME_MESH_PREVIOUS_MASTER_KEYS: %w", err)
	}
	masterKey := getEnv("HOME_MESH_MASTER_KEY", "")
	if masterKey == "" && len(previousMasterKeys) > 0 {
		return Config{}, errors.New("HOME_MESH_PREVIOUS_MASTER_KEYS requires HOME_MESH_MASTER_KEY")
	}

	return Config{
		HTTPAddr:               getEnv("HOME_MESH_HTTP_ADDR", ":8080"),
		AppName:                getEnv("HOME_MESH_APP_NAME", "home-mesh"),
		Env:                    getEnv("HOME_MESH_ENV", "development"),
		DBPath:                 getEnv("HOME_MESH_DB_PATH", "data/home-mesh.db"),
		NmapPath:               getEnv("HOME_MESH_NMAP_PATH", defaultNmapPath()),
		DiscoveryAllowPublic:   discoveryAllowPublic,
		SeedDemoData:           seedDemoData,
		MasterKeyBase:          masterKey,
		MasterKeyVersion:       masterKeyVersion,
		PreviousMasterKeys:     previousMasterKeys,
		SSHHostKeyMode:         getEnv("HOME_MESH_SSH_HOST_KEY_MODE", defaultSSHHostKeyMode()),
		KnownHostsPath:         getEnv("HOME_MESH_SSH_KNOWN_HOSTS_PATH", defaultKnownHostsPath()),
		SessionSecret:          getEnv("HOME_MESH_SESSION_SECRET", ""),
		AuthDisabled:           authDisabled,
		TrustedProxyCIDRs:      trustedProxyCIDRs,
		BootstrapAdminUsername: getEnv("HOME_MESH_BOOTSTRAP_ADMIN_USERNAME", "root"),
		BootstrapAdminPassword: getEnv("HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD", ""),
		ScanInterval:           scanInterval,
	}, nil
}

func commaSeparatedValues(value string) []string {
	var values []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func parseBool(key string, fallback bool) (bool, error) {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if value == "" {
		return fallback, nil
	}
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be true or false", key)
	}
}

func defaultNmapPath() string {
	if os.PathSeparator == '\\' {
		return "nmap.exe"
	}

	return "nmap"
}

func defaultSSHHostKeyMode() string {
	return "known_hosts"
}

func defaultKnownHostsPath() string {
	userHome, err := os.UserHomeDir()
	if err != nil || userHome == "" {
		return ""
	}

	return userHome + string(os.PathSeparator) + ".ssh" + string(os.PathSeparator) + "known_hosts"
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func parseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < 5*time.Second {
		return 0, errors.New("must be at least 5s")
	}
	return d, nil
}

func parsePositiveInt(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return parsed, nil
}

func parseVersionedKeys(value string) (map[int]string, error) {
	keys := make(map[int]string)
	for _, entry := range commaSeparatedValues(value) {
		versionText, encodedKey, ok := strings.Cut(entry, ":")
		if !ok || strings.TrimSpace(encodedKey) == "" {
			return nil, fmt.Errorf("entry %q must use version:base64 format", entry)
		}
		version, err := strconv.Atoi(strings.TrimSpace(versionText))
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("entry %q has an invalid version", entry)
		}
		if _, duplicate := keys[version]; duplicate {
			return nil, fmt.Errorf("version %d is repeated", version)
		}
		keys[version] = strings.TrimSpace(encodedKey)
	}
	return keys, nil
}
