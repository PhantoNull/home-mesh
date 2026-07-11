package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRouterDrainWaitsForHijackedTerminal(t *testing.T) {
	t.Parallel()

	tracker := newTerminalConnectionTracker()
	release, ok := tracker.acquire()
	if !ok {
		t.Fatal("initial terminal connection was rejected")
	}

	tracker.beginDrain()
	if _, ok := tracker.acquire(); ok {
		t.Fatal("terminal connection was accepted after drain started")
	}

	waitContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := tracker.wait(waitContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait with active terminal = %v, want deadline exceeded", err)
	}

	release()
	release()
	if err := tracker.wait(context.Background()); err != nil {
		t.Fatalf("wait after terminal audit completed: %v", err)
	}
}

func TestRouterDrainWithoutTerminalsCompletesImmediately(t *testing.T) {
	t.Parallel()

	tracker := newTerminalConnectionTracker()
	tracker.beginDrain()
	if err := tracker.wait(context.Background()); err != nil {
		t.Fatalf("wait without terminals: %v", err)
	}
}

func TestRouterDrainOutlivesHTTPShutdownForHijackedWebSocket(t *testing.T) {
	t.Parallel()

	tracker := newTerminalConnectionTracker()
	upgraded := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		release, ok := tracker.acquire()
		if !ok {
			http.Error(w, "draining", http.StatusServiceUnavailable)
			return
		}
		defer release()
		connection, err := (&websocket.Upgrader{}).Upgrade(w, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		close(upgraded)
		<-request.Context().Done()
	})
	router := &Router{handler: handler, terminalConnections: tracker}
	serviceContext, cancelService := context.WithCancel(context.Background())
	defer cancelService()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{
		Handler: router,
		BaseContext: func(net.Listener) context.Context {
			return serviceContext
		},
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		cancelService()
		_ = server.Close()
	})

	client, _, err := websocket.DefaultDialer.Dial("ws://"+listener.Addr().String(), nil)
	if err != nil {
		t.Fatalf("dial WebSocket: %v", err)
	}
	defer client.Close()
	select {
	case <-upgraded:
	case <-time.After(time.Second):
		t.Fatal("WebSocket handler did not upgrade")
	}

	router.BeginDrain()
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
		t.Fatalf("HTTP shutdown: %v", err)
	}
	select {
	case err := <-serveDone:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("serve error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP server did not stop")
	}

	waitContext, cancelWait := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := router.WaitForDrain(waitContext); !errors.Is(err, context.DeadlineExceeded) {
		cancelWait()
		t.Fatalf("hijacked drain before cancellation = %v", err)
	}
	cancelWait()

	cancelService()
	finalContext, cancelFinal := context.WithTimeout(context.Background(), time.Second)
	defer cancelFinal()
	if err := router.WaitForDrain(finalContext); err != nil {
		t.Fatalf("hijacked drain after cancellation: %v", err)
	}
}
