package api

import (
	"net/http"

	"github.com/PhantoNull/home-mesh/internal/secrets"
	"golang.org/x/crypto/ssh"
)

const sshUnavailableReason = "Secure SSH access is unavailable."

func sshAccessAvailable(secretService *secrets.Service, hostKeyCallback ssh.HostKeyCallback) bool {
	return secretService != nil && hostKeyCallback != nil
}

func writeSSHUnavailable(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "secure SSH access is unavailable"})
}
