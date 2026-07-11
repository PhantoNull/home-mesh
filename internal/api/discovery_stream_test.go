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

func TestDiscoveryScanStreamSanitizesTerminalErrors(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		err         error
		wantMessage string
		secret      string
	}{
		{
			name:        "network not allowed",
			err:         errors.Join(discovery.ErrNetworkNotAllowed, errors.New("network-policy-secret")),
			wantMessage: "the requested network is not allowed",
			secret:      "network-policy-secret",
		},
		{
			name:        "nmap unavailable",
			err:         errors.Join(discovery.ErrNmapUnavailable, errors.New("nmap-path-secret")),
			wantMessage: "nmap is not available in the current runtime",
			secret:      "nmap-path-secret",
		},
		{
			name:        "deadline",
			err:         errors.Join(context.DeadlineExceeded, errors.New("deadline-detail-secret")),
			wantMessage: "discovery scan timed out",
			secret:      "deadline-detail-secret",
		},
		{
			name:        "upstream execution",
			err:         errors.New("upstream-stderr-secret"),
			wantMessage: "discovery scan failed",
			secret:      "upstream-stderr-secret",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			inventory := newDiscoveryTestStore(t)
			writer := newControlledStreamWriter()
			handleDiscoveryScanStream(inventory, &fakeDiscoveryScanner{streamErr: test.err}).ServeHTTP(
				writer,
				httptest.NewRequest(http.MethodGet, "/api/discovery/scan/stream", nil),
			)

			body := writer.BodyString()
			if !strings.Contains(body, "event: discovery-error") || !strings.Contains(body, test.wantMessage) {
				t.Fatalf("unexpected body: %q", body)
			}
			if strings.Contains(body, test.secret) {
				t.Fatalf("stream exposed internal error detail %q: %q", test.secret, body)
			}
		})
	}
}

func TestDiscoveryScanStreamRejectsInvalidCIDRWithoutScanning(t *testing.T) {
	t.Parallel()

	inventory := newDiscoveryTestStore(t)
	scanner := &fakeDiscoveryScanner{
		stream: func(context.Context, string, func(discovery.HostMatch) error) (discovery.ScanResult, error) {
			t.Fatal("scanner called for invalid CIDR")
			return discovery.ScanResult{}, nil
		},
	}
	writer := newControlledStreamWriter()
	handleDiscoveryScanStream(inventory, scanner).ServeHTTP(
		writer,
		httptest.NewRequest(http.MethodGet, "/api/discovery/scan/stream?cidr=not-a-cidr", nil),
	)

	body := writer.BodyString()
	if !strings.Contains(body, "event: discovery-error") || !strings.Contains(body, "discovery CIDR must be a valid IPv4 network") {
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

func TestDiscoveryScanRejectsInvalidRequestsWithoutScanning(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: `{"cidr":`},
		{name: "invalid CIDR", body: `{"cidr":"not-a-cidr"}`},
		{name: "oversized network", body: `{"cidr":"10.0.0.0/8"}`},
		{name: "IPv6", body: `{"cidr":"fd00::/64"}`},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			scanner := &fakeDiscoveryScanner{
				scan: func(context.Context, string) (discovery.ScanResult, error) {
					t.Fatal("scanner called for invalid request")
					return discovery.ScanResult{}, nil
				},
			}
			recorder := httptest.NewRecorder()
			handleDiscoveryScan(nil, scanner).ServeHTTP(
				recorder,
				httptest.NewRequest(http.MethodPost, "/api/discovery/scan", strings.NewReader(test.body)),
			)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestDiscoveryScanMapsAndSanitizesServiceErrors(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		err         error
		wantStatus  int
		wantMessage string
		secret      string
	}{
		{
			name:        "network not allowed",
			err:         errors.Join(discovery.ErrNetworkNotAllowed, errors.New("network-policy-secret")),
			wantStatus:  http.StatusForbidden,
			wantMessage: "the requested network is not allowed",
			secret:      "network-policy-secret",
		},
		{
			name:        "nmap unavailable",
			err:         errors.Join(discovery.ErrNmapUnavailable, errors.New("nmap-path-secret")),
			wantStatus:  http.StatusServiceUnavailable,
			wantMessage: "nmap is not available in the current runtime",
			secret:      "nmap-path-secret",
		},
		{
			name:        "deadline",
			err:         errors.Join(context.DeadlineExceeded, errors.New("deadline-detail-secret")),
			wantStatus:  http.StatusGatewayTimeout,
			wantMessage: "discovery scan timed out",
			secret:      "deadline-detail-secret",
		},
		{
			name:        "upstream execution",
			err:         errors.New("upstream-stderr-secret"),
			wantStatus:  http.StatusBadGateway,
			wantMessage: "discovery scan failed",
			secret:      "upstream-stderr-secret",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			handleDiscoveryScan(nil, &fakeDiscoveryScanner{scanErr: test.err}).ServeHTTP(
				recorder,
				httptest.NewRequest(http.MethodPost, "/api/discovery/scan", strings.NewReader(`{"cidr":"203.0.113.0/24"}`)),
			)

			if recorder.Code != test.wantStatus || !strings.Contains(recorder.Body.String(), test.wantMessage) {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), test.secret) {
				t.Fatalf("response exposed internal error detail %q: %s", test.secret, recorder.Body.String())
			}
		})
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
	scan         func(context.Context, string) (discovery.ScanResult, error)
	stream       func(context.Context, string, func(discovery.HostMatch) error) (discovery.ScanResult, error)
}

func (f *fakeDiscoveryScanner) Capabilities() discovery.Capabilities {
	return f.capabilities
}

func (f *fakeDiscoveryScanner) ScanCIDR(ctx context.Context, cidr string) (discovery.ScanResult, error) {
	if f.scan != nil {
		return f.scan(ctx, cidr)
	}
	return f.scanResult, f.scanErr
}

func (f *fakeDiscoveryScanner) ScanCIDRStream(ctx context.Context, cidr string, onHost func(discovery.HostMatch) error) (discovery.ScanResult, error) {
	if f.stream != nil {
		return f.stream(ctx, cidr, onHost)
	}
	return f.streamResult, f.streamErr
}
