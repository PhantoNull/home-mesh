package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewHTTPServerAllowsLongLivedStreamingResponses(t *testing.T) {
	t.Parallel()

	handlerCalled := false
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalled = true
	})
	baseContext, cancel := context.WithCancel(context.Background())
	server := newHTTPServer("127.0.0.1:0", handler, baseContext)

	if server.Addr != "127.0.0.1:0" {
		t.Fatalf("Addr = %q, want 127.0.0.1:0", server.Addr)
	}
	server.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !handlerCalled {
		t.Fatal("Handler was not preserved")
	}
	if got := server.BaseContext(nil); got != baseContext {
		t.Fatal("BaseContext was not preserved")
	}
	cancel()
	select {
	case <-server.BaseContext(nil).Done():
	default:
		t.Fatal("server request base context did not observe cancellation")
	}
	if server.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout = %s, want 0 for streaming handlers", server.WriteTimeout)
	}
	if server.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s, want 10s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 15*time.Second {
		t.Fatalf("ReadTimeout = %s, want 15s", server.ReadTimeout)
	}
	if server.IdleTimeout != 120*time.Second {
		t.Fatalf("IdleTimeout = %s, want 120s", server.IdleTimeout)
	}
}
