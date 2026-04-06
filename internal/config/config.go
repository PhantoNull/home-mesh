package config

import (
	"os"
	"time"
)

type Config struct {
	HTTPAddr               string
	AppName                string
	Env                    string
	DBPath                 string
	NmapPath               string
	MasterKeyBase          string
	SSHHostKeyMode         string
	KnownHostsPath         string
	SessionSecret          string
	BootstrapAdminUsername string
	BootstrapAdminPassword string
	ScanInterval           time.Duration
}

func Load() Config {
	return Config{
		HTTPAddr:               getEnv("HOME_MESH_HTTP_ADDR", ":8080"),
		AppName:                getEnv("HOME_MESH_APP_NAME", "home-mesh"),
		Env:                    getEnv("HOME_MESH_ENV", "development"),
		DBPath:                 getEnv("HOME_MESH_DB_PATH", "data/home-mesh.db"),
		NmapPath:               getEnv("HOME_MESH_NMAP_PATH", defaultNmapPath()),
		MasterKeyBase:          getEnv("HOME_MESH_MASTER_KEY", ""),
		SSHHostKeyMode:         getEnv("HOME_MESH_SSH_HOST_KEY_MODE", defaultSSHHostKeyMode()),
		KnownHostsPath:         getEnv("HOME_MESH_SSH_KNOWN_HOSTS_PATH", defaultKnownHostsPath()),
		SessionSecret:          getEnv("HOME_MESH_SESSION_SECRET", ""),
		BootstrapAdminUsername: getEnv("HOME_MESH_BOOTSTRAP_ADMIN_USERNAME", "root"),
		BootstrapAdminPassword: getEnv("HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD", ""),
		ScanInterval:           parseDuration(getEnv("HOME_MESH_SCAN_INTERVAL", "30s")),
	}
}

func defaultNmapPath() string {
	if os.PathSeparator == '\\' {
		return "nmap.exe"
	}

	return "nmap"
}

func defaultSSHHostKeyMode() string {
	if getEnv("HOME_MESH_ENV", "development") == "development" {
		return "insecure"
	}

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

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d < 5*time.Second {
		return 30 * time.Second
	}
	return d
}
