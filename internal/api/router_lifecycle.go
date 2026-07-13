package api

import (
	"context"
	"net/http"
	"sync"
)

// Router owns HTTP routing plus the hijacked terminal connections that
// net/http cannot drain on its own.
type Router struct {
	handler             http.Handler
	terminalConnections *terminalConnectionTracker
}

func (r *Router) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	r.handler.ServeHTTP(w, request)
}

// BeginDrain prevents new terminal upgrades while ordinary HTTP shutdown is in
// progress.
func (r *Router) BeginDrain() {
	r.terminalConnections.beginDrain()
}

// WaitForDrain waits until every terminal handler has completed its final audit.
func (r *Router) WaitForDrain(ctx context.Context) error {
	return r.terminalConnections.wait(ctx)
}

type terminalConnectionTracker struct {
	mu       sync.Mutex
	active   int
	draining bool
	drained  chan struct{}
}

func newTerminalConnectionTracker() *terminalConnectionTracker {
	return &terminalConnectionTracker{drained: make(chan struct{})}
}

func (t *terminalConnectionTracker) acquire() (func(), bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.draining {
		return nil, false
	}
	t.active++

	var once sync.Once
	return func() {
		once.Do(t.release)
	}, true
}

func (t *terminalConnectionTracker) release() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active--
	if t.draining && t.active == 0 {
		close(t.drained)
	}
}

func (t *terminalConnectionTracker) beginDrain() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.draining {
		return
	}
	t.draining = true
	if t.active == 0 {
		close(t.drained)
	}
}

func (t *terminalConnectionTracker) wait(ctx context.Context) error {
	t.beginDrain()
	select {
	case <-t.drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
