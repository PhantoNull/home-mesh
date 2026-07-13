package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PhantoNull/home-mesh/internal/monitor"
)

func TestSynchronousOperationExtendsWriteDeadlineAndBoundsContext(t *testing.T) {
	t.Parallel()

	writer := &deadlineResponseWriter{header: make(http.Header)}
	request := httptest.NewRequest(http.MethodPost, "/api/discovery/scan", nil)
	startedAt := time.Now()
	boundedRequest, finish := withSynchronousOperationDeadline(writer, request)

	deadline, ok := boundedRequest.Context().Deadline()
	if !ok {
		t.Fatal("synchronous operation context has no deadline")
	}
	if remaining := deadline.Sub(startedAt); remaining < synchronousOperationTimeout-time.Second || remaining > synchronousOperationTimeout+time.Second {
		t.Fatalf("operation deadline remaining = %s", remaining)
	}
	if len(writer.deadlines) != 1 {
		t.Fatalf("write deadline calls = %d, want 1", len(writer.deadlines))
	}
	if remaining := writer.deadlines[0].Sub(startedAt); remaining < synchronousWriteTimeout-time.Second || remaining > synchronousWriteTimeout+time.Second {
		t.Fatalf("write deadline remaining = %s", remaining)
	}

	finish()
	if len(writer.deadlines) != 1 {
		t.Fatalf("write deadlines after finish = %v", writer.deadlines)
	}
	select {
	case <-boundedRequest.Context().Done():
		if boundedRequest.Context().Err() != context.Canceled {
			t.Fatalf("operation context error = %v", boundedRequest.Context().Err())
		}
	default:
		t.Fatal("operation context was not canceled by finish")
	}
}

func TestInventoryRefreshUsesBoundedContextAndReportsTimeout(t *testing.T) {
	t.Parallel()

	refresher := refreshAllFunc(func(ctx context.Context) (monitor.RefreshResult, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > synchronousOperationTimeout {
			t.Fatalf("refresh context deadline = %v, present = %t", deadline, ok)
		}
		return monitor.RefreshResult{}, context.DeadlineExceeded
	})
	recorder := httptest.NewRecorder()
	handleInventoryRefresh(nil, refresher).ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodPost, "/api/devices/refresh", nil),
	)

	if recorder.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["error"] != "inventory refresh timed out" {
		t.Fatalf("error = %q", response["error"])
	}
}

type deadlineResponseWriter struct {
	header    http.Header
	deadlines []time.Time
}

func (w *deadlineResponseWriter) Header() http.Header {
	return w.header
}

func (w *deadlineResponseWriter) Write(body []byte) (int, error) {
	return len(body), nil
}

func (w *deadlineResponseWriter) WriteHeader(int) {}

func (w *deadlineResponseWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}
