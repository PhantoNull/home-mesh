package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/home-mesh/internal/config"
	"github.com/PhantoNull/home-mesh/internal/store"
)

func TestHashAndVerifyPassword(t *testing.T) {
	t.Parallel()

	hash, err := hashPassword("s3cret-pass")
	if err != nil {
		t.Fatalf("hashPassword returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("hashPassword returned empty hash")
	}
	if !verifyPassword("s3cret-pass", hash) {
		t.Fatal("verifyPassword rejected correct password")
	}
	if verifyPassword("wrong-pass", hash) {
		t.Fatal("verifyPassword accepted wrong password")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	t.Parallel()

	if verifyPassword("irrelevant", "not-a-valid-hash") {
		t.Fatal("verifyPassword accepted malformed hash")
	}
}

func TestVerifyPasswordRejectsUntrustedArgon2Parameters(t *testing.T) {
	t.Parallel()

	hash, err := hashPassword("s3cret-pass")
	if err != nil {
		t.Fatalf("hashPassword returned error: %v", err)
	}
	parts := strings.Split(hash, "$")
	parts[2] = strconv.FormatUint(uint64(argon2Memory)+1, 10)

	if verifyPassword("s3cret-pass", strings.Join(parts, "$")) {
		t.Fatal("verifyPassword accepted untrusted Argon2 parameters")
	}
}

func TestNewAuthManagerFailsClosedWithoutSessionSecret(t *testing.T) {
	t.Parallel()

	if _, err := newAuthManager(config.Config{}, nil, newTestRequestMetadata(t)); err == nil {
		t.Fatal("expected missing session secret to fail closed")
	}
}

func TestNewAuthManagerAllowsExplicitDisabledMode(t *testing.T) {
	t.Parallel()

	auth, err := newAuthManager(config.Config{AuthDisabled: true}, nil, newTestRequestMetadata(t))
	if err != nil {
		t.Fatalf("newAuthManager returned error: %v", err)
	}
	if auth.enabled {
		t.Fatal("expected explicit disabled mode")
	}
}

func TestNewAuthManagerRejectsShortSessionSecret(t *testing.T) {
	t.Parallel()

	_, err := newAuthManager(config.Config{SessionSecret: "too-short"}, nil, newTestRequestMetadata(t))
	if err == nil {
		t.Fatal("expected short session secret to be rejected")
	}
}

func TestHandleLoginRateLimitBlocksSixthFailure(t *testing.T) {
	t.Parallel()

	auth := newTestAuthManager(t)
	now := time.Date(2026, 4, 7, 12, 0, 0, 0, time.UTC)
	auth.loginLimiter.now = func() time.Time { return now }

	for i := 0; i < loginMaxAttempts; i++ {
		recorder := httptest.NewRecorder()
		auth.handleLogin(recorder, newLoginRequest(t, "admin", "wrong-pass"))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d want %d", i+1, recorder.Code, http.StatusUnauthorized)
		}
	}

	recorder := httptest.NewRecorder()
	auth.handleLogin(recorder, newLoginRequest(t, "admin", "wrong-pass"))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d want %d", recorder.Code, http.StatusTooManyRequests)
	}
	if got := recorder.Header().Get("Retry-After"); got != strconv.Itoa(int(loginWindowPeriod/time.Second)) {
		t.Fatalf("got Retry-After %q want %q", got, strconv.Itoa(int(loginWindowPeriod/time.Second)))
	}
}

func TestHandleLoginSuccessResetsRateLimit(t *testing.T) {
	t.Parallel()

	auth := newTestAuthManager(t)

	recorder := httptest.NewRecorder()
	auth.handleLogin(recorder, newLoginRequest(t, "admin", "wrong-pass"))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("got %d want %d", recorder.Code, http.StatusUnauthorized)
	}

	recorder = httptest.NewRecorder()
	auth.handleLogin(recorder, newLoginRequest(t, "admin", "s3cret-pass"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("got %d want %d", recorder.Code, http.StatusOK)
	}

	for i := 0; i < loginMaxAttempts; i++ {
		recorder = httptest.NewRecorder()
		auth.handleLogin(recorder, newLoginRequest(t, "admin", "wrong-pass"))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("post-reset attempt %d: got %d want %d", i+1, recorder.Code, http.StatusUnauthorized)
		}
	}

	recorder = httptest.NewRecorder()
	auth.handleLogin(recorder, newLoginRequest(t, "admin", "wrong-pass"))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d want %d", recorder.Code, http.StatusTooManyRequests)
	}
}

func TestHandleLoginWindowExpiryAllowsRetry(t *testing.T) {
	t.Parallel()

	auth := newTestAuthManager(t)
	now := time.Date(2026, 4, 7, 12, 0, 0, 0, time.UTC)
	auth.loginLimiter.now = func() time.Time { return now }

	for i := 0; i < loginMaxAttempts; i++ {
		recorder := httptest.NewRecorder()
		auth.handleLogin(recorder, newLoginRequest(t, "admin", "wrong-pass"))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d want %d", i+1, recorder.Code, http.StatusUnauthorized)
		}
	}

	recorder := httptest.NewRecorder()
	auth.handleLogin(recorder, newLoginRequest(t, "admin", "wrong-pass"))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d want %d before expiry", recorder.Code, http.StatusTooManyRequests)
	}

	now = now.Add(loginWindowPeriod + time.Second)

	recorder = httptest.NewRecorder()
	auth.handleLogin(recorder, newLoginRequest(t, "admin", "wrong-pass"))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("got %d want %d after expiry", recorder.Code, http.StatusUnauthorized)
	}
}

func TestHandleLoginRateLimitRetryAfterTracksRemainingWindow(t *testing.T) {
	t.Parallel()

	auth := newTestAuthManager(t)
	now := time.Date(2026, 4, 7, 12, 0, 0, 0, time.UTC)
	auth.loginLimiter.now = func() time.Time { return now }

	for i := 0; i < loginMaxAttempts; i++ {
		recorder := httptest.NewRecorder()
		auth.handleLogin(recorder, newLoginRequest(t, "admin", "wrong-pass"))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d want %d", i+1, recorder.Code, http.StatusUnauthorized)
		}
		now = now.Add(time.Minute)
	}

	recorder := httptest.NewRecorder()
	auth.handleLogin(recorder, newLoginRequest(t, "admin", "wrong-pass"))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d want %d", recorder.Code, http.StatusTooManyRequests)
	}
	if got := recorder.Header().Get("Retry-After"); got != strconv.Itoa(int((10*time.Minute)/time.Second)) {
		t.Fatalf("got Retry-After %q want %q", got, strconv.Itoa(int((10*time.Minute)/time.Second)))
	}
}

func TestClientIPResolvesForwardedChainFromRightToLeft(t *testing.T) {
	t.Parallel()

	requests := newTestRequestMetadata(t, "172.16.0.0/12")
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "172.20.0.2:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 172.18.0.8")

	if got := requests.clientIP(req); got != "203.0.113.10" {
		t.Fatalf("got %q want %q", got, "203.0.113.10")
	}
}

func TestClientIPIgnoresPrivatePeerOutsideTrustedCIDRs(t *testing.T) {
	t.Parallel()

	requests := newTestRequestMetadata(t, "172.16.0.0/12")
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "192.168.1.42:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	if got := requests.clientIP(req); got != "192.168.1.42" {
		t.Fatalf("got %q want %q", got, "192.168.1.42")
	}
}

func TestHandleLoginSetsSecureCookieForTrustedHTTPSProxy(t *testing.T) {
	t.Parallel()

	auth := newTestAuthManager(t)
	req := newLoginRequest(t, "admin", "s3cret-pass")
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	recorder := httptest.NewRecorder()

	auth.handleLogin(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("got %d want %d", recorder.Code, http.StatusOK)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName {
		t.Fatalf("unexpected response cookies: %v", cookies)
	}
	if !cookies[0].Secure {
		t.Fatal("expected session cookie to be Secure behind trusted HTTPS proxy")
	}
}

func TestLogoutRevokesIssuedSession(t *testing.T) {
	t.Parallel()

	auth := newTestAuthManager(t)
	loginRecorder := httptest.NewRecorder()
	auth.handleLogin(loginRecorder, newLoginRequest(t, "admin", "s3cret-pass"))
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status = %d", loginRecorder.Code)
	}
	cookies := loginRecorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies = %v", cookies)
	}

	authenticatedRequest := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	authenticatedRequest.AddCookie(cookies[0])
	if _, ok := auth.authenticatedUsername(authenticatedRequest); !ok {
		t.Fatal("issued session was not accepted")
	}

	logoutRequest := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	logoutRequest.AddCookie(cookies[0])
	auth.handleLogout(httptest.NewRecorder(), logoutRequest)
	if _, ok := auth.authenticatedUsername(authenticatedRequest); ok {
		t.Fatal("revoked session remained valid")
	}
}

func TestHandleLoginBoundsConcurrentPasswordChecks(t *testing.T) {
	t.Parallel()

	auth := newTestAuthManager(t)
	for range maxConcurrentPasswordChecks {
		auth.passwordSlots <- struct{}{}
	}
	defer func() {
		for range maxConcurrentPasswordChecks {
			<-auth.passwordSlots
		}
	}()

	recorder := httptest.NewRecorder()
	auth.handleLogin(recorder, newLoginRequest(t, "admin", "s3cret-pass"))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if recorder.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q", recorder.Header().Get("Retry-After"))
	}
}

func TestSessionRegistryIsBoundedAndExpiresEntries(t *testing.T) {
	t.Parallel()

	registry := newSessionRegistry()
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	registry.now = func() time.Time { return now }
	registry.register("expired", now.Add(-time.Second))
	for index := 0; index <= maxActiveSessions; index++ {
		registry.register(strconv.Itoa(index), now.Add(time.Duration(index+1)*time.Second))
	}
	if len(registry.sessions) != maxActiveSessions {
		t.Fatalf("session count = %d, want %d", len(registry.sessions), maxActiveSessions)
	}
	if registry.valid("expired", now.Add(-time.Second)) {
		t.Fatal("expired session remained valid")
	}
}

func newTestAuthManager(t *testing.T) *authManager {
	t.Helper()

	hash, err := hashPassword("s3cret-pass")
	if err != nil {
		t.Fatalf("hashPassword returned error: %v", err)
	}

	return &authManager{
		enabled:         true,
		account:         store.AdminAccount{Username: "admin", PasswordHash: hash},
		sessionSecret:   []byte("0123456789abcdef0123456789abcdef"),
		sessionDuration: time.Hour,
		sessions:        newSessionRegistry(),
		passwordSlots:   make(chan struct{}, maxConcurrentPasswordChecks),
		loginLimiter:    newLoginRateLimiter(),
		requests:        newTestRequestMetadata(t),
	}
}

func newTestRequestMetadata(t *testing.T, cidrs ...string) *requestMetadata {
	t.Helper()

	requests, err := newRequestMetadata(cidrs)
	if err != nil {
		t.Fatalf("newRequestMetadata returned error: %v", err)
	}
	return requests
}

func newLoginRequest(t *testing.T, username string, password string) *http.Request {
	t.Helper()

	body, err := json.Marshal(loginPayload{Username: username, Password: password})
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "198.51.100.7:1234"
	req.Header.Set("Content-Type", "application/json")
	return req
}
