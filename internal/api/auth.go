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
	"fmt"
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

const (
	minSessionSecretBytes = 32
	minBootstrapPassword  = 12
	argon2SaltLen         = 16
)

type authManager struct {
	enabled         bool
	account         store.AdminAccount
	sessionSecret   []byte
	sessionDuration time.Duration
	sessions        *sessionRegistry
	passwordSlots   chan struct{}
	loginLimiter    *loginRateLimiter
	requests        *requestMetadata
}

const (
	loginMaxAttempts            = 5
	loginWindowPeriod           = 15 * time.Minute
	maxLoginTrackIPs            = 1024
	maxActiveSessions           = 1024
	maxConcurrentPasswordChecks = 2
	maxLoginUsernameBytes       = 128
	maxLoginPasswordBytes       = 1024
)

type sessionRegistry struct {
	mu           sync.Mutex
	sessions     map[string]*sessionEntry
	now          func() time.Time
	newLifecycle func(time.Time) (context.Context, context.CancelFunc)
}

type sessionEntry struct {
	expiresAt       time.Time
	lifecycle       context.Context
	cancelLifecycle context.CancelFunc
	stopExpiry      func() bool
	bindings        map[*sessionBinding]context.CancelFunc
}

type sessionBinding struct{}

type sessionTermination struct {
	stopExpiry      func() bool
	cancelLifecycle context.CancelFunc
	cancelBindings  []context.CancelFunc
}

type sessionClaims struct {
	username  string
	nonce     string
	expiresAt time.Time
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		sessions: make(map[string]*sessionEntry),
		now:      time.Now,
		newLifecycle: func(expiresAt time.Time) (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), expiresAt)
		},
	}
}

func (r *sessionRegistry) register(nonce string, expiresAt time.Time) {
	if r == nil {
		return
	}
	expiresAt = time.Unix(expiresAt.Unix(), 0).UTC()
	now := r.currentTime()
	if !now.Before(expiresAt) {
		return
	}
	lifecycle, cancelLifecycle := r.createLifecycle(expiresAt)
	entry := &sessionEntry{
		expiresAt:       expiresAt,
		lifecycle:       lifecycle,
		cancelLifecycle: cancelLifecycle,
		bindings:        make(map[*sessionBinding]context.CancelFunc),
	}

	r.mu.Lock()
	terminated := r.pruneLocked()
	if current, exists := r.sessions[nonce]; exists {
		delete(r.sessions, nonce)
		terminated = append(terminated, detachSessionEntryLocked(current))
	}
	if len(r.sessions) >= maxActiveSessions {
		var earliestNonce string
		var earliestExpiry time.Time
		for candidate, current := range r.sessions {
			if earliestNonce == "" || current.expiresAt.Before(earliestExpiry) {
				earliestNonce = candidate
				earliestExpiry = current.expiresAt
			}
		}
		terminated = append(terminated, detachSessionEntryLocked(r.sessions[earliestNonce]))
		delete(r.sessions, earliestNonce)
	}
	if r.sessions == nil {
		r.sessions = make(map[string]*sessionEntry)
	}
	r.sessions[nonce] = entry
	r.mu.Unlock()
	terminateSessions(terminated)

	stopExpiry := context.AfterFunc(lifecycle, func() {
		r.expire(nonce, entry)
	})
	r.mu.Lock()
	if r.sessions[nonce] == entry {
		entry.stopExpiry = stopExpiry
		stopExpiry = nil
	}
	r.mu.Unlock()
	if stopExpiry != nil {
		stopExpiry()
	}
}

func (r *sessionRegistry) valid(nonce string, expiresAt time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	terminated := r.pruneLocked()
	entry, ok := r.sessions[nonce]
	valid := ok && entry.expiresAt.Unix() == expiresAt.Unix() && entry.lifecycle.Err() == nil
	r.mu.Unlock()
	terminateSessions(terminated)
	return valid
}

func (r *sessionRegistry) bind(parent context.Context, nonce string, expiresAt time.Time) (context.Context, func(), bool) {
	if r == nil {
		return parent, nil, false
	}

	r.mu.Lock()
	terminated := r.pruneLocked()
	entry, ok := r.sessions[nonce]
	if !ok || entry.expiresAt.Unix() != expiresAt.Unix() || entry.lifecycle.Err() != nil {
		r.mu.Unlock()
		terminateSessions(terminated)
		return parent, nil, false
	}

	boundContext, cancel := context.WithCancel(parent)
	binding := &sessionBinding{}
	entry.bindings[binding] = cancel
	r.mu.Unlock()
	terminateSessions(terminated)

	var once sync.Once
	release := func() {
		once.Do(func() {
			r.mu.Lock()
			if current := r.sessions[nonce]; current == entry {
				delete(entry.bindings, binding)
			}
			r.mu.Unlock()
			cancel()
		})
	}
	return boundContext, release, true
}

func (r *sessionRegistry) revoke(nonce string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	entry := r.sessions[nonce]
	delete(r.sessions, nonce)
	terminated := detachSessionEntryLocked(entry)
	r.mu.Unlock()
	terminateSessions([]sessionTermination{terminated})
}

func (r *sessionRegistry) pruneLocked() []sessionTermination {
	now := r.currentTime()
	terminated := make([]sessionTermination, 0)
	for nonce, entry := range r.sessions {
		if !now.Before(entry.expiresAt) || entry.lifecycle.Err() != nil {
			delete(r.sessions, nonce)
			terminated = append(terminated, detachSessionEntryLocked(entry))
		}
	}
	return terminated
}

func (r *sessionRegistry) expire(nonce string, expected *sessionEntry) {
	if r == nil || expected == nil {
		return
	}
	r.mu.Lock()
	if r.sessions[nonce] != expected {
		r.mu.Unlock()
		return
	}
	delete(r.sessions, nonce)
	terminated := detachSessionEntryLocked(expected)
	r.mu.Unlock()
	terminateSessions([]sessionTermination{terminated})
}

// detachSessionEntryLocked transfers every cancellation handle out of an entry.
// Callers must hold the registry mutex while invoking it.
func detachSessionEntryLocked(entry *sessionEntry) sessionTermination {
	if entry == nil {
		return sessionTermination{}
	}
	terminated := sessionTermination{
		stopExpiry:      entry.stopExpiry,
		cancelLifecycle: entry.cancelLifecycle,
		cancelBindings:  make([]context.CancelFunc, 0, len(entry.bindings)),
	}
	entry.stopExpiry = nil
	entry.cancelLifecycle = nil
	for binding, cancel := range entry.bindings {
		terminated.cancelBindings = append(terminated.cancelBindings, cancel)
		delete(entry.bindings, binding)
	}
	return terminated
}

func terminateSessions(terminations []sessionTermination) {
	for _, terminated := range terminations {
		if terminated.stopExpiry != nil {
			terminated.stopExpiry()
		}
		if terminated.cancelLifecycle != nil {
			terminated.cancelLifecycle()
		}
		for _, cancel := range terminated.cancelBindings {
			cancel()
		}
	}
}

func (r *sessionRegistry) currentTime() time.Time {
	if r.now == nil {
		return time.Now()
	}
	return r.now()
}

func (r *sessionRegistry) createLifecycle(expiresAt time.Time) (context.Context, context.CancelFunc) {
	if r.newLifecycle == nil {
		return context.WithDeadline(context.Background(), expiresAt)
	}
	return r.newLifecycle(expiresAt)
}

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

func newAuthManager(cfg config.Config, inventory *store.Store, requests *requestMetadata) (*authManager, error) {
	if requests == nil {
		return nil, errors.New("request metadata policy is required")
	}
	if cfg.AuthDisabled {
		return &authManager{enabled: false, requests: requests}, nil
	}

	sessionSecret := strings.TrimSpace(cfg.SessionSecret)
	if sessionSecret == "" {
		return nil, errors.New("HOME_MESH_SESSION_SECRET is required; set HOME_MESH_AUTH_DISABLED=true only for an intentionally unauthenticated runtime")
	}
	if len(sessionSecret) < minSessionSecretBytes {
		return nil, fmt.Errorf("HOME_MESH_SESSION_SECRET must contain at least %d bytes", minSessionSecretBytes)
	}

	account, err := inventory.GetAdminAccount(context.Background())
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		bootstrapPassword := cfg.BootstrapAdminPassword
		if bootstrapPassword == "" {
			return nil, errors.New("HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD is required until the first admin account is created")
		}
		if len(bootstrapPassword) < minBootstrapPassword {
			return nil, fmt.Errorf("HOME_MESH_BOOTSTRAP_ADMIN_PASSWORD must contain at least %d bytes", minBootstrapPassword)
		}
		bootstrapUsername := strings.TrimSpace(cfg.BootstrapAdminUsername)
		if bootstrapUsername == "" {
			return nil, errors.New("HOME_MESH_BOOTSTRAP_ADMIN_USERNAME must not be empty")
		}
		hash, hashErr := hashPassword(bootstrapPassword)
		if hashErr != nil {
			return nil, hashErr
		}
		account, err = inventory.BootstrapAdminAccount(context.Background(), bootstrapUsername, hash)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	sessionDuration := cfg.SessionDuration
	if sessionDuration == 0 {
		sessionDuration = time.Hour
	}
	if sessionDuration < 5*time.Minute || sessionDuration > 24*time.Hour {
		return nil, errors.New("session duration must be between 5m and 24h")
	}

	return &authManager{
		enabled:         true,
		account:         account,
		sessionSecret:   []byte(sessionSecret),
		sessionDuration: sessionDuration,
		sessions:        newSessionRegistry(),
		passwordSlots:   make(chan struct{}, maxConcurrentPasswordChecks),
		loginLimiter:    newLoginRateLimiter(),
		requests:        requests,
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

	clientIP := a.requests.clientIP(r)
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
	if handleJSONDecodeError(w, decodeJSON(r, &payload), "invalid login payload") {
		return
	}
	if len(payload.Username) > maxLoginUsernameBytes || len(payload.Password) > maxLoginPasswordBytes {
		a.loginLimiter.recordFailure(clientIP)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	passwordValid, available := a.verifyPasswordBounded(payload.Password)
	if !available {
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authentication capacity is busy; retry shortly"})
		return
	}
	usernameValid := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(payload.Username)), []byte(a.account.Username)) == 1
	if !usernameValid || !passwordValid {
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

	// #nosec G124 -- Secure is derived from direct TLS or a configured trusted proxy.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   a.requests.isSecureRequest(r),
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
	a.revokeRequestSession(r)

	// #nosec G124 -- Secure is derived from direct TLS or a configured trusted proxy.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   a.requests.isSecureRequest(r),
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
		if r.Method == http.MethodOptions || r.URL.Path == "/api/health" || r.URL.Path == "/api/ready" || r.URL.Path == "/api/auth/session" || r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/logout" {
			next.ServeHTTP(w, r)
			return
		}
		claims, ok := a.sessionClaims(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		requestContext, release, ok := a.sessions.bind(r.Context(), claims.nonce, claims.expiresAt)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		defer release()

		next.ServeHTTP(w, r.WithContext(requestContext))
	})
}

func (a *authManager) authenticatedUsername(r *http.Request) (string, bool) {
	if !a.enabled {
		return "", true
	}
	claims, ok := a.sessionClaims(r)
	if !ok || !a.sessions.valid(claims.nonce, claims.expiresAt) {
		return "", false
	}
	return claims.username, true
}

func (a *authManager) sessionClaims(r *http.Request) (sessionClaims, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return sessionClaims{}, false
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 4 {
		return sessionClaims{}, false
	}

	usernameBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return sessionClaims{}, false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return sessionClaims{}, false
	}
	expiresAt, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return sessionClaims{}, false
	}
	expiresAtTime := time.Unix(expiresAt, 0).UTC()
	if !time.Now().UTC().Before(expiresAtTime) {
		return sessionClaims{}, false
	}

	expected := a.signSession(parts[0], parts[1], parts[2], nonce)
	if subtle.ConstantTimeCompare([]byte(parts[3]), []byte(expected)) != 1 {
		return sessionClaims{}, false
	}

	username := string(usernameBytes)
	if subtle.ConstantTimeCompare([]byte(username), []byte(a.account.Username)) != 1 {
		return sessionClaims{}, false
	}
	return sessionClaims{username: username, nonce: parts[1], expiresAt: expiresAtTime}, true
}

func (a *authManager) newSessionValue(username string) (string, time.Time, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, err
	}

	duration := a.sessionDuration
	if duration == 0 {
		duration = time.Hour
	}
	expiresAt := time.Now().UTC().Add(duration).Truncate(time.Second)
	userPart := base64.RawURLEncoding.EncodeToString([]byte(username))
	noncePart := base64.RawURLEncoding.EncodeToString(nonce)
	expiresPart := strconv.FormatInt(expiresAt.Unix(), 10)
	signature := a.signSession(userPart, noncePart, expiresPart, nonce)
	if a.sessions == nil {
		a.sessions = newSessionRegistry()
	}
	a.sessions.register(noncePart, expiresAt)

	return strings.Join([]string{userPart, noncePart, expiresPart, signature}, "."), expiresAt, nil
}

func (a *authManager) verifyPasswordBounded(password string) (valid bool, available bool) {
	if a.passwordSlots == nil {
		return verifyPassword(password, a.account.PasswordHash), true
	}
	select {
	case a.passwordSlots <- struct{}{}:
		defer func() { <-a.passwordSlots }()
		return verifyPassword(password, a.account.PasswordHash), true
	default:
		return false, false
	}
}

func (a *authManager) revokeRequestSession(r *http.Request) {
	if a.sessions == nil {
		return
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) == 4 {
		a.sessions.revoke(parts[1])
	}
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
	if timeCost != argon2Time || memoryCost != argon2Memory || threads != argon2Threads {
		return false
	}
	if len(salt) != argon2SaltLen || len(expected) != argon2KeyLen {
		return false
	}

	actual := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
