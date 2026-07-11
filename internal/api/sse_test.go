package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PhantoNull/home-mesh/internal/monitor"
)

func TestHandleSSERejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	handleSSE(monitor.NewEventBus()).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/events", nil))

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow = %q, want %q", got, http.MethodGet)
	}
}

func TestHandleSSEStreamsHeadersAndEventsUntilCancelled(t *testing.T) {
	t.Parallel()

	bus := monitor.NewEventBus()
	writer := newControlledStreamWriter()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSSE(bus).ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx))
	}()

	waitForFlush(t, writer.flushes)
	bus.Publish(monitor.ScanEvent{Kind: monitor.EventScanStarted, Data: []byte(`{"deviceIds":[],"nodeIds":[]}`)})
	waitForFlush(t, writer.flushes)
	cancel()
	waitForHandler(t, done)

	if got := writer.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", got)
	}
	if got := writer.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache", got)
	}
	if got := writer.Header().Get("X-Accel-Buffering"); got != "no" {
		t.Fatalf("X-Accel-Buffering = %q, want no", got)
	}
	body := writer.BodyString()
	for _, want := range []string{": connected\n\n", "id: ", "event: scan\n", `"kind":"scan-started"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body %q does not contain %q", body, want)
		}
	}
}

func TestHandleSSEReplaysEventsAfterLastEventID(t *testing.T) {
	t.Parallel()

	bus := monitor.NewEventBusWithOptions(monitor.EventBusOptions{Generation: "generation-a"})
	first := bus.Publish(monitor.ScanEvent{Kind: monitor.EventScanStarted, Data: []byte(`{"sequence":1}`)})
	bus.Publish(monitor.ScanEvent{Kind: monitor.EventDeviceUpdate, Data: []byte(`{"sequence":2}`)})

	writer := newControlledStreamWriter()
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	request.Header.Set("Last-Event-ID", first.Cursor())
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSSE(bus).ServeHTTP(writer, request)
	}()
	waitForFlush(t, writer.flushes)
	waitForFlush(t, writer.flushes)
	cancel()
	waitForHandler(t, done)

	body := writer.BodyString()
	if strings.Contains(body, `"sequence":1`) || !strings.Contains(body, `"sequence":2`) {
		t.Fatalf("unexpected replay body: %q", body)
	}
}

func TestHandleSSESignalsResetForUnavailableHistory(t *testing.T) {
	t.Parallel()

	bus := monitor.NewEventBusWithOptions(monitor.EventBusOptions{Generation: "generation-a"})
	writer := newControlledStreamWriter()
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	request.Header.Set("Last-Event-ID", "old-generation:42")
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSSE(bus).ServeHTTP(writer, request)
	}()
	waitForFlush(t, writer.flushes)
	waitForFlush(t, writer.flushes)
	cancel()
	waitForHandler(t, done)

	body := writer.BodyString()
	if !strings.Contains(body, `"kind":"stream-reset"`) || !strings.Contains(body, `"reason":"history-unavailable"`) {
		t.Fatalf("reset event missing from body: %q", body)
	}
}

func TestHandleSSEReturnsOnInitialWriteError(t *testing.T) {
	t.Parallel()

	writer := newControlledStreamWriter()
	writer.writeErr = errors.New("client disconnected")
	assertSSEHandlerReturns(t, writer)
}

func TestHandleSSEReturnsOnInitialFlushError(t *testing.T) {
	t.Parallel()

	writer := newControlledStreamWriter()
	writer.flushErr = errors.New("client disconnected")
	assertSSEHandlerReturns(t, writer)
}

func assertSSEHandlerReturns(t *testing.T, writer *controlledStreamWriter) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSSE(monitor.NewEventBus()).ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx))
	}()

	select {
	case <-done:
		cancel()
	case <-time.After(250 * time.Millisecond):
		cancel()
		waitForHandler(t, done)
		t.Fatal("SSE handler did not return after the client write failed")
	}
}

func waitForFlush(t *testing.T, flushes <-chan struct{}) {
	t.Helper()
	select {
	case <-flushes:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE flush")
	}
}

func waitForHandler(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE handler to return")
	}
}

type controlledStreamWriter struct {
	mu       sync.Mutex
	header   http.Header
	body     bytes.Buffer
	status   int
	writes   int
	failAt   int
	writeErr error
	flushErr error
	flushes  chan struct{}
}

func newControlledStreamWriter() *controlledStreamWriter {
	return &controlledStreamWriter{
		header:  make(http.Header),
		flushes: make(chan struct{}, 8),
	}
}

func (w *controlledStreamWriter) Header() http.Header {
	return w.header
}

func (w *controlledStreamWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.status == 0 {
		w.status = status
	}
}

func (w *controlledStreamWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes++
	if w.writeErr != nil && (w.failAt == 0 || w.writes >= w.failAt) {
		return 0, w.writeErr
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(data)
}

func (w *controlledStreamWriter) Flush() {
	_ = w.FlushError()
}

func (w *controlledStreamWriter) FlushError() error {
	select {
	case w.flushes <- struct{}{}:
	default:
	}
	return w.flushErr
}

func (w *controlledStreamWriter) BodyString() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.String()
}
