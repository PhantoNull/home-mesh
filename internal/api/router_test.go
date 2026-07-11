package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PhantoNull/home-mesh/internal/config"
)

func TestNormalizeSSHPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "default", input: "", want: "22"},
		{name: "numeric", input: "2222", want: "2222"},
		{name: "service name", input: "ssh", want: "ssh"},
		{name: "invalid", input: "99999", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeSSHPort(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestIsSameOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		scheme string
		host   string
		origin string
		want   bool
	}{
		{name: "same host and port", scheme: "http", host: "example.com:5173", origin: "http://example.com:5173", want: true},
		{name: "scheme case is ignored", scheme: "http", host: "example.com:5173", origin: "HTTP://EXAMPLE.COM:5173", want: true},
		{name: "default https port matches", scheme: "https", host: "example.com:443", origin: "https://example.com", want: true},
		{name: "cross scheme is rejected", scheme: "https", host: "example.com", origin: "http://example.com", want: false},
		{name: "different port", scheme: "http", host: "example.com:8080", origin: "http://example.com:5173", want: false},
		{name: "malformed origin", scheme: "http", host: "example.com:5173", origin: "://bad-origin", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isSameOrigin(tt.scheme, tt.host, tt.origin); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestWithCORSAllowsMatchingOriginAndPreservesVary(t *testing.T) {
	t.Parallel()

	nextCalled := false
	handler := withOriginPolicy(newTestRequestMetadata(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Host = "localhost:5173"
	req.Header.Set("Origin", "http://localhost:5173")
	recorder := httptest.NewRecorder()
	recorder.Header().Add("Vary", "Accept-Encoding")

	handler.ServeHTTP(recorder, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("got %q want %q", got, "http://localhost:5173")
	}
	if got := recorder.Header().Values("Vary"); len(got) != 2 || got[0] != "Accept-Encoding" || got[1] != "Origin" {
		t.Fatalf("unexpected Vary values: %v", got)
	}
}

func TestOriginPolicyRejectsMismatchedPOSTBeforeHandler(t *testing.T) {
	t.Parallel()

	nextCalled := false
	handler := withOriginPolicy(newTestRequestMetadata(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/devices", strings.NewReader("device=delete"))
	req.Host = "localhost:8080"
	req.Header.Set("Origin", "http://localhost:5173")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if nextCalled {
		t.Fatal("mismatched POST reached the application handler")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("got %d want %d", recorder.Code, http.StatusForbidden)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("got %q want empty", got)
	}
}

func TestWithCORSOptionsShortCircuits(t *testing.T) {
	t.Parallel()

	nextCalled := false
	handler := withOriginPolicy(newTestRequestMetadata(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/health", nil)
	req.Host = "localhost:5173"
	req.Header.Set("Origin", "http://localhost:5173")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if nextCalled {
		t.Fatal("expected OPTIONS request to short-circuit")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("got %d want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestWebSocketOriginUsesCanonicalHostAndTrustedForwardedProto(t *testing.T) {
	t.Parallel()

	requests := newTestRequestMetadata(t)
	req := httptest.NewRequest(http.MethodGet, "/api/ws", nil)
	req.RemoteAddr = "127.0.0.1:4000"
	req.Host = "home.example"
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", "https://home.example")

	if !requests.checkWebSocketOrigin(req) {
		t.Fatal("expected canonical request host to be accepted")
	}
}

func TestNewRouterRejectsInvalidTrustedProxyCIDR(t *testing.T) {
	t.Parallel()

	_, err := NewRouter(config.Config{TrustedProxyCIDRs: []string{"not-a-cidr"}}, nil, nil, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "HOME_MESH_TRUSTED_PROXY_CIDRS") {
		t.Fatalf("got error %v, want invalid trusted proxy CIDR error", err)
	}
}
