package config

import "os"

type Config struct {
	HTTPAddr       string
	AppName        string
	Env            string
	DBPath         string
	MasterKeyBase  string
	SSHHostKeyMode string
	KnownHostsPath string
}

func Load() Config {
	return Config{
		HTTPAddr:       getEnv("HOME_MESH_HTTP_ADDR", ":8080"),
		AppName:        getEnv("HOME_MESH_APP_NAME", "home-mesh"),
		Env:            getEnv("HOME_MESH_ENV", "development"),
		DBPath:         getEnv("HOME_MESH_DB_PATH", "data/home-mesh.db"),
		MasterKeyBase:  getEnv("HOME_MESH_MASTER_KEY", ""),
		SSHHostKeyMode: getEnv("HOME_MESH_SSH_HOST_KEY_MODE", defaultSSHHostKeyMode()),
		KnownHostsPath: getEnv("HOME_MESH_SSH_KNOWN_HOSTS_PATH", defaultKnownHostsPath()),
	}
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
