package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PhantoNull/home-mesh/internal/config"
)

const sessionCookieName = "home_mesh_session"

type authManager struct {
	enabled       bool
	username      string
	password      string
	sessionSecret []byte
}

type loginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authSessionResponse struct {
	Enabled       bool   `json:"enabled"`
	Authenticated bool   `json:"authenticated"`
	Username      string `json:"username,omitempty"`
}

func newAuthManager(cfg config.Config) *authManager {
	enabled := strings.TrimSpace(cfg.AuthUsername) != "" &&
		cfg.AuthPassword != "" &&
		strings.TrimSpace(cfg.SessionSecret) != ""

	return &authManager{
		enabled:       enabled,
		username:      strings.TrimSpace(cfg.AuthUsername),
		password:      cfg.AuthPassword,
		sessionSecret: []byte(strings.TrimSpace(cfg.SessionSecret)),
	}
}

func (a *authManager) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	if !a.enabled {
		writeJSON(w, http.StatusOK, authSessionResponse{Enabled: false, Authenticated: true})
		return
	}

	username, ok := a.authenticatedUsername(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, authSessionResponse{Enabled: true, Authenticated: false})
		return
	}

	writeJSON(w, http.StatusOK, authSessionResponse{
		Enabled:       true,
		Authenticated: true,
		Username:      username,
	})
}

func (a *authManager) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	if !a.enabled {
		writeJSON(w, http.StatusOK, authSessionResponse{Enabled: false, Authenticated: true})
		return
	}

	var payload loginPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid login payload"})
		return
	}

	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(payload.Username)), []byte(a.username)) != 1 ||
		subtle.ConstantTimeCompare([]byte(payload.Password), []byte(a.password)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	cookieValue, expiresAt, err := a.newSessionValue(a.username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})

	writeJSON(w, http.StatusOK, authSessionResponse{
		Enabled:       true,
		Authenticated: true,
		Username:      a.username,
	})
}

func (a *authManager) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *authManager) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || !a.enabled {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodOptions || r.URL.Path == "/api/health" || r.URL.Path == "/api/auth/session" || r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/logout" {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := a.authenticatedUsername(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *authManager) authenticatedUsername(r *http.Request) (string, bool) {
	if !a.enabled {
		return "", true
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 4 {
		return "", false
	}

	usernameBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	expiresAt, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", false
	}
	if time.Now().UTC().Unix() > expiresAt {
		return "", false
	}

	expected := a.signSession(parts[0], parts[1], parts[2], nonce)
	if subtle.ConstantTimeCompare([]byte(parts[3]), []byte(expected)) != 1 {
		return "", false
	}

	username := string(usernameBytes)
	if subtle.ConstantTimeCompare([]byte(username), []byte(a.username)) != 1 {
		return "", false
	}

	return username, true
}

func (a *authManager) newSessionValue(username string) (string, time.Time, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, err
	}

	expiresAt := time.Now().UTC().Add(time.Hour)
	userPart := base64.RawURLEncoding.EncodeToString([]byte(username))
	noncePart := base64.RawURLEncoding.EncodeToString(nonce)
	expiresPart := strconv.FormatInt(expiresAt.Unix(), 10)
	signature := a.signSession(userPart, noncePart, expiresPart, nonce)

	return strings.Join([]string{userPart, noncePart, expiresPart, signature}, "."), expiresAt, nil
}

func (a *authManager) signSession(userPart string, noncePart string, expiresPart string, nonce []byte) string {
	mac := hmac.New(sha256.New, a.sessionSecret)
	encoder := json.NewEncoder(mac)
	_ = encoder.Encode([]string{userPart, noncePart, expiresPart, hex.EncodeToString(nonce)})
	return hex.EncodeToString(mac.Sum(nil))
}
