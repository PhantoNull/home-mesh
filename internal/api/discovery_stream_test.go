package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/home-mesh/internal/discovery"
	"github.com/PhantoNull/home-mesh/internal/store"
)

func TestDiscoveryScanStreamRejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	handleDiscoveryScanStream(nil, &fakeDiscoveryScanner{}).ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodPost, "/api/discovery/scan/stream", nil),
	)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
	if got := recorder.Header().Get("Allow"); got != http.MethodGet {
		t.Fatalf("Allow = %q, want %q", got, http.MethodGet)
	}
}

func TestDiscoveryScanStreamWritesHostAndCompletionEvents(t *testing.T) {
	t.Parallel()

	inventory := newDiscoveryTestStore(t)
	host := discovery.HostMatch{IPAddress: "203.0.113.10", Hostname: "edge-host"}
	scanner := &fakeDiscoveryScanner{
		stream: func(_ context.Context, cidr string, onHost func(discovery.HostMatch) error) (discovery.ScanResult, error) {
			if cidr != "203.0.113.0/24" {
				t.Fatalf("cidr = %q, want 203.0.113.0/24", cidr)
			}
			if err := onHost(host); err != nil {
				return discovery.ScanResult{}, err
			}
			return discovery.ScanResult{
				Provider:     "nmap",
				CIDR:         cidr,
				ScannedCIDRs: []string{cidr},
				Hosts:        []discovery.HostMatch{host},
			}, nil
		},
	}
	writer := newControlledStreamWriter()

	handleDiscoveryScanStream(inventory, scanner).ServeHTTP(
		writer,
		httptest.NewRequest(http.MethodGet, "/api/discovery/scan/stream?cidr=203.0.113.0%2F24", nil),
	)

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
	for _, want := range []string{
		": connected\n\n",
		"event: discovery-host\n",
		`"ipAddress":"203.0.113.10"`,
		"event: discovery-complete\n",
		`"scannedCidrs":["203.0.113.0/24"]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body %q does not contain %q", body, want)
		}
	}
}

func TestDiscoveryScanStreamStopsQuietlyWhenRequestIsCancelled(t *testing.T) {
	t.Parallel()

	inventory := newDiscoveryTestStore(t)
	started := make(chan struct{})
	scanner := &fakeDiscoveryScanner{
		stream: func(ctx context.Context, _ string, _ func(discovery.HostMatch) error) (discovery.ScanResult, error) {
			close(started)
			<-ctx.Done()
			return discovery.ScanResult{}, ctx.Err()
		},
	}
	writer := newControlledStreamWriter()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleDiscoveryScanStream(inventory, scanner).ServeHTTP(
			writer,
			httptest.NewRequest(http.MethodGet, "/api/discovery/scan/stream", nil).WithContext(ctx),
		)
	}()

	waitForFlush(t, writer.flushes)
	<-started
	cancel()
	waitForHandler(t, done)

	body := writer.BodyString()
	if strings.Contains(body, "event: discovery-error") || strings.Contains(body, "event: discovery-complete") {
		t.Fatalf("cancelled stream wrote a terminal event: %q", body)
	}
}

func TestDiscoveryScanStreamMapsScanInProgress(t *testing.T) {
	t.Parallel()

	inventory := newDiscoveryTestStore(t)
	scanner := &fakeDiscoveryScanner{streamErr: discovery.ErrScanInProgress}
	writer := newControlledStreamWriter()

	handleDiscoveryScanStream(inventory, scanner).ServeHTTP(
		writer,
		httptest.NewRequest(http.MethodGet, "/api/discovery/scan/stream", nil),
	)

	body := writer.BodyString()
	if !strings.Contains(body, "event: discovery-error") || !strings.Contains(body, "a discovery scan is already in progress") {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestDiscoveryScanStreamPropagatesClientWriteFailure(t *testing.T) {
	t.Parallel()

	inventory := newDiscoveryTestStore(t)
	callbackErr := make(chan error, 1)
	scanner := &fakeDiscoveryScanner{
		stream: func(_ context.Context, _ string, onHost func(discovery.HostMatch) error) (discovery.ScanResult, error) {
			err := onHost(discovery.HostMatch{IPAddress: "203.0.113.20"})
			callbackErr <- err
			return discovery.ScanResult{}, err
		},
	}
	writer := newControlledStreamWriter()
	writer.failAt = 2
	writer.writeErr = errors.New("client disconnected")

	handleDiscoveryScanStream(inventory, scanner).ServeHTTP(
		writer,
		httptest.NewRequest(http.MethodGet, "/api/discovery/scan/stream", nil),
	)

	if err := <-callbackErr; !errors.Is(err, errSSETransport) {
		t.Fatalf("callback error = %v, want SSE transport error", err)
	}
	if body := writer.BodyString(); strings.Contains(body, "event: discovery-error") {
		t.Fatalf("transport failure triggered another event: %q", body)
	}
}

func TestDiscoveryScanMapsScanInProgressToConflict(t *testing.T) {
	t.Parallel()

	scanner := &fakeDiscoveryScanner{scanErr: discovery.ErrScanInProgress}
	recorder := httptest.NewRecorder()
	handleDiscoveryScan(nil, scanner).ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodPost, "/api/discovery/scan", strings.NewReader(`{"cidr":"203.0.113.0/24"}`)),
	)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
	}
	if !strings.Contains(recorder.Body.String(), "a discovery scan is already in progress") {
		t.Fatalf("unexpected body: %q", recorder.Body.String())
	}
}

func newDiscoveryTestStore(t *testing.T) *store.Store {
	t.Helper()
	inventory, err := store.New(filepath.Join(t.TempDir(), "home-mesh.db"))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() {
		if err := inventory.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return inventory
}

type fakeDiscoveryScanner struct {
	capabilities discovery.Capabilities
	scanResult   discovery.ScanResult
	scanErr      error
	streamResult discovery.ScanResult
	streamErr    error
	stream       func(context.Context, string, func(discovery.HostMatch) error) (discovery.ScanResult, error)
}

func (f *fakeDiscoveryScanner) Capabilities() discovery.Capabilities {
	return f.capabilities
}

func (f *fakeDiscoveryScanner) ScanCIDR(context.Context, string) (discovery.ScanResult, error) {
	return f.scanResult, f.scanErr
}

func (f *fakeDiscoveryScanner) ScanCIDRStream(ctx context.Context, cidr string, onHost func(discovery.HostMatch) error) (discovery.ScanResult, error) {
	if f.stream != nil {
		return f.stream(ctx, cidr, onHost)
	}
	return f.streamResult, f.streamErr
}
