package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PhantoNull/home-mesh/internal/config"
	"github.com/PhantoNull/home-mesh/internal/store"
	"golang.org/x/crypto/argon2"
)

const sessionCookieName = "home_mesh_session"

type authManager struct {
	enabled       bool
	account       store.AdminAccount
	sessionSecret []byte
	loginLimiter  *loginRateLimiter
}

const (
	loginMaxAttempts  = 5
	loginWindowPeriod = 15 * time.Minute
	maxLoginTrackIPs  = 1024
)

type loginAttemptRecord struct {
	failures  int
	windowEnd time.Time
}

type loginRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttemptRecord
	now      func() time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		attempts: make(map[string]*loginAttemptRecord),
		now:      time.Now,
	}
}

func (l *loginRateLimiter) allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.pruneExpiredLocked(now)
	record, exists := l.attempts[ip]
	if !exists {
		return true, 0
	}

	if now.After(record.windowEnd) {
		delete(l.attempts, ip)
		return true, 0
	}

	if record.failures < loginMaxAttempts {
		return true, 0
	}

	retryAfter := record.windowEnd.Sub(now)
	if retryAfter < time.Second {
		retryAfter = time.Second
	}

	return false, retryAfter
}

func (l *loginRateLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.pruneExpiredLocked(now)
	record, exists := l.attempts[ip]
	if !exists || now.After(record.windowEnd) {
		if len(l.attempts) >= maxLoginTrackIPs {
			l.evictOldestLocked()
		}
		l.attempts[ip] = &loginAttemptRecord{
			failures:  1,
			windowEnd: now.Add(loginWindowPeriod),
		}
		return
	}

	record.failures++
}

func (l *loginRateLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

func (l *loginRateLimiter) pruneExpiredLocked(now time.Time) {
	for ip, record := range l.attempts {
		if now.After(record.windowEnd) {
			delete(l.attempts, ip)
		}
	}
}

func (l *loginRateLimiter) evictOldestLocked() {
	var (
		oldestIP  string
		oldestSet bool
		oldestEnd time.Time
	)

	for ip, record := range l.attempts {
		if !oldestSet || record.windowEnd.Before(oldestEnd) {
			oldestIP = ip
			oldestEnd = record.windowEnd
			oldestSet = true
		}
	}
	if oldestSet {
		delete(l.attempts, oldestIP)
	}
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

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
)

func newAuthManager(cfg config.Config, inventory *store.Store) (*authManager, error) {
	sessionSecret := strings.TrimSpace(cfg.SessionSecret)
	if sessionSecret == "" {
		return &authManager{enabled: false}, nil
	}

	account, err := inventory.GetAdminAccount(context.Background())
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		bootstrapPassword := cfg.BootstrapAdminPassword
		if bootstrapPassword == "" {
			return nil, errors.New("HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD is required until the first admin account is created")
		}
		hash, hashErr := hashPassword(bootstrapPassword)
		if hashErr != nil {
			return nil, hashErr
		}
		account, err = inventory.BootstrapAdminAccount(context.Background(), strings.TrimSpace(cfg.BootstrapAdminUsername), hash)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	return &authManager{
		enabled:       true,
		account:       account,
		sessionSecret: []byte(sessionSecret),
		loginLimiter:  newLoginRateLimiter(),
	}, nil
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

	clientIP := extractClientIP(r)
	if allowed, retryAfter := a.loginLimiter.allow(clientIP); !allowed {
		retryAfterSeconds := int(retryAfter.Round(time.Second) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":               "too many login attempts, try again later",
			"retry_after_seconds": retryAfterSeconds,
		})
		return
	}

	var payload loginPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid login payload"})
		return
	}

	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(payload.Username)), []byte(a.account.Username)) != 1 ||
		!verifyPassword(payload.Password, a.account.PasswordHash) {
		a.loginLimiter.recordFailure(clientIP)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	a.loginLimiter.reset(clientIP)

	cookieValue, expiresAt, err := a.newSessionValue(a.account.Username)
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
		Username:      a.account.Username,
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
	if subtle.ConstantTimeCompare([]byte(username), []byte(a.account.Username)) != 1 {
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

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return strings.Join([]string{
		"argon2id",
		strconv.Itoa(argon2Time),
		strconv.Itoa(argon2Memory),
		strconv.Itoa(argon2Threads),
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	}, "$"), nil
}

func verifyPassword(password string, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "argon2id" {
		return false
	}

	timeCost, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	memoryCost, err := strconv.Atoi(parts[2])
	if err != nil {
		return false
	}
	threads, err := strconv.Atoi(parts[3])
	if err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	actual := argon2.IDKey([]byte(password), salt, uint32(timeCost), uint32(memoryCost), uint8(threads), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
