package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
		host   string
		origin string
		want   bool
	}{
		{name: "same host and port", host: "example.com:5173", origin: "http://example.com:5173", want: true},
		{name: "scheme case is ignored", host: "example.com:5173", origin: "HTTP://EXAMPLE.COM:5173", want: true},
		{name: "default https port matches", host: "example.com:443", origin: "https://example.com", want: true},
		{name: "different port", host: "example.com:8080", origin: "http://example.com:5173", want: false},
		{name: "malformed origin", host: "example.com:5173", origin: "://bad-origin", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isSameOrigin(tt.host, tt.origin); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestWithCORSAllowsMatchingOriginAndPreservesVary(t *testing.T) {
	t.Parallel()

	nextCalled := false
	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestWithCORSRejectsMismatchedOrigin(t *testing.T) {
	t.Parallel()

	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Host = "localhost:8080"
	req.Header.Set("Origin", "http://localhost:5173")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("got %q want empty", got)
	}
}

func TestWithCORSOptionsShortCircuits(t *testing.T) {
	t.Parallel()

	nextCalled := false
	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestCheckWebSocketOriginUsesForwardedHostFromTrustedProxy(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/ws", nil)
	req.RemoteAddr = "127.0.0.1:4000"
	req.Host = "127.0.0.1:8080"
	req.Header.Set("X-Forwarded-Host", "localhost:5173")
	req.Header.Set("Origin", "http://localhost:5173")

	if !checkWebSocketOrigin(req) {
		t.Fatal("expected trusted forwarded host to be accepted")
	}
}
