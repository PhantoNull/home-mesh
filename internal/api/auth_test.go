package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestHandleLoginRateLimitBlocksSixthFailure(t *testing.T) {
	t.Parallel()

	auth := newTestAuthManager(t)

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

func TestExtractClientIPUsesForwardedHeadersFromTrustedProxy(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 127.0.0.1")

	if got := extractClientIP(req); got != "203.0.113.10" {
		t.Fatalf("got %q want %q", got, "203.0.113.10")
	}
}

func TestExtractClientIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.RemoteAddr = "198.51.100.7:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	if got := extractClientIP(req); got != "198.51.100.7" {
		t.Fatalf("got %q want %q", got, "198.51.100.7")
	}
}

func newTestAuthManager(t *testing.T) *authManager {
	t.Helper()

	hash, err := hashPassword("s3cret-pass")
	if err != nil {
		t.Fatalf("hashPassword returned error: %v", err)
	}

	return &authManager{
		enabled:       true,
		account:       store.AdminAccount{Username: "admin", PasswordHash: hash},
		sessionSecret: []byte("0123456789abcdef0123456789abcdef"),
		loginLimiter:  newLoginRateLimiter(),
	}
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
