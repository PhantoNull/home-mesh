package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTerminalBridgeRemoteExitDoesNotWaitForBrowser(t *testing.T) {
	session := newFakeTerminalSession(bytes.NewReader(nil), bytes.NewReader(nil))
	socket := newFakeTerminalSocket()
	resultDone := runTerminalBridgeAsync(context.Background(), socket, session)

	session.waitResult <- nil
	result := awaitTerminalResult(t, resultDone)
	if result.Err != nil || result.TerminationReason != "remote_exit" {
		t.Fatalf("result = %+v, want clean remote exit", result)
	}
	assertTerminalClosedOnce(t, socket, session)
	assertTerminalMessage(t, socket.messages(), terminalServerMessage{Type: "status", Data: "connected"})
	assertTerminalMessage(t, socket.messages(), terminalServerMessage{Type: "status", Data: "closed"})
	if got := socket.readLimit.Load(); got != terminalReadLimit {
		t.Fatalf("read limit = %d, want %d", got, terminalReadLimit)
	}
	if socket.readDeadlineCount.Load() == 0 || socket.writeDeadlineCount.Load() == 0 {
		t.Fatal("terminal socket deadlines were not configured")
	}
	if got := socket.maxConcurrentWriters.Load(); got != 1 {
		t.Fatalf("max concurrent WebSocket writers = %d, want 1", got)
	}
}

func TestTerminalBridgeBrowserExitClosesAndReapsSSH(t *testing.T) {
	session := newFakeTerminalSession(bytes.NewReader(nil), bytes.NewReader(nil))
	socket := newFakeTerminalSocket()
	socket.reads <- fakeTerminalRead{message: terminalClientMessage{Type: "close"}}

	result := awaitTerminalResult(t, runTerminalBridgeAsync(context.Background(), socket, session))
	if result.Err != nil || result.TerminationReason != "client_close" {
		t.Fatalf("result = %+v, want clean client close", result)
	}
	assertTerminalClosedOnce(t, socket, session)
	if got := session.waitCalls.Load(); got != 1 {
		t.Fatalf("session Wait calls = %d, want 1", got)
	}
	assertTerminalMessage(t, socket.messages(), terminalServerMessage{Type: "status", Data: "closed"})
}

func TestTerminalBridgeBackpressureTerminatesWithoutBlockingProducers(t *testing.T) {
	outputSize := (terminalOutboundCapacity + 4) * terminalOutputChunkBytes
	session := newFakeTerminalSession(bytes.NewReader(bytes.Repeat([]byte("x"), outputSize)), bytes.NewReader(nil))
	socket := newFakeTerminalSocket()
	socket.blockWrites = true

	startedAt := time.Now()
	result := awaitTerminalResult(t, runTerminalBridgeAsync(context.Background(), socket, session))
	if !errors.Is(result.Err, errTerminalOutputBackpressure) || result.TerminationReason != "backpressure" {
		t.Fatalf("result = %+v, want output backpressure", result)
	}
	if elapsed := time.Since(startedAt); elapsed > 2*time.Second {
		t.Fatalf("backpressured bridge took %s to stop", elapsed)
	}
	assertTerminalClosedOnce(t, socket, session)
	if got := socket.maxConcurrentWriters.Load(); got != 1 {
		t.Fatalf("max concurrent WebSocket writers = %d, want 1", got)
	}
}

func TestTerminalBridgeCancellationClosesSocketAndSSH(t *testing.T) {
	session := newFakeTerminalSession(bytes.NewReader(nil), bytes.NewReader(nil))
	socket := newFakeTerminalSocket()
	ctx, cancel := context.WithCancel(context.Background())
	resultDone := runTerminalBridgeAsync(ctx, socket, session)

	select {
	case <-socket.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("terminal writer did not start")
	}
	cancel()

	result := awaitTerminalResult(t, resultDone)
	if !errors.Is(result.Err, context.Canceled) || result.TerminationReason != "context_cancelled" {
		t.Fatalf("result = %+v, want context cancellation", result)
	}
	assertTerminalClosedOnce(t, socket, session)
}

func TestTerminalBridgeExtendsReadDeadlineForApplicationMessages(t *testing.T) {
	session := newFakeTerminalSession(bytes.NewReader(nil), bytes.NewReader(nil))
	socket := newFakeTerminalSocket()
	socket.reads <- fakeTerminalRead{message: terminalClientMessage{Type: "ping"}}
	socket.reads <- fakeTerminalRead{message: terminalClientMessage{Type: "close"}}

	result := awaitTerminalResult(t, runTerminalBridgeAsync(context.Background(), socket, session))
	if result.Err != nil {
		t.Fatalf("run terminal bridge: %v", result.Err)
	}
	if got := socket.readDeadlineCount.Load(); got < 3 {
		t.Fatalf("read deadline updates = %d, want initial deadline plus one per message", got)
	}
	assertTerminalMessage(t, socket.messages(), terminalServerMessage{Type: "pong"})
}

func TestTerminalBridgeRejectsOversizedClientCommands(t *testing.T) {
	tests := []struct {
		name    string
		message terminalClientMessage
	}{
		{name: "input", message: terminalClientMessage{Type: "input", Data: string(bytes.Repeat([]byte("x"), terminalMaxInputBytes+1))}},
		{name: "columns", message: terminalClientMessage{Type: "resize", Cols: terminalMaxCols + 1, Rows: 24}},
		{name: "rows", message: terminalClientMessage{Type: "resize", Cols: 80, Rows: terminalMaxRows + 1}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newFakeTerminalSession(bytes.NewReader(nil), bytes.NewReader(nil))
			socket := newFakeTerminalSocket()
			socket.reads <- fakeTerminalRead{message: test.message}

			result := awaitTerminalResult(t, runTerminalBridgeAsync(context.Background(), socket, session))
			if result.Err == nil || result.TerminationReason != "protocol_error" {
				t.Fatalf("result = %+v, want protocol error", result)
			}
			if session.writeCalls.Load() != 0 || session.resizeCalls.Load() != 0 {
				t.Fatal("invalid client command reached the SSH session")
			}
		})
	}
}

func runTerminalBridgeAsync(ctx context.Context, socket terminalSocket, session terminalSession) <-chan terminalBridgeResult {
	result := make(chan terminalBridgeResult, 1)
	go func() {
		result <- runTerminalBridge(ctx, socket, session)
	}()
	return result
}

func awaitTerminalResult(t *testing.T, result <-chan terminalBridgeResult) terminalBridgeResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("terminal bridge did not stop")
		return terminalBridgeResult{}
	}
}

func assertTerminalClosedOnce(t *testing.T, socket *fakeTerminalSocket, session *fakeTerminalSession) {
	t.Helper()
	if got := socket.closeCalls.Load(); got != 1 {
		t.Fatalf("socket Close calls = %d, want 1", got)
	}
	if got := session.closeCalls.Load(); got != 1 {
		t.Fatalf("session Close calls = %d, want 1", got)
	}
}

func assertTerminalMessage(t *testing.T, messages []terminalServerMessage, want terminalServerMessage) {
	t.Helper()
	for _, message := range messages {
		if message == want {
			return
		}
	}
	t.Fatalf("messages = %+v, missing %+v", messages, want)
}

type fakeTerminalSession struct {
	stdout io.Reader
	stderr io.Reader

	waitResult chan error
	closed     chan struct{}
	closeOnce  sync.Once

	waitCalls   atomic.Int32
	closeCalls  atomic.Int32
	writeCalls  atomic.Int32
	resizeCalls atomic.Int32
}

func newFakeTerminalSession(stdout io.Reader, stderr io.Reader) *fakeTerminalSession {
	return &fakeTerminalSession{
		stdout:     stdout,
		stderr:     stderr,
		waitResult: make(chan error, 1),
		closed:     make(chan struct{}),
	}
}

func (s *fakeTerminalSession) Stdout() io.Reader { return s.stdout }
func (s *fakeTerminalSession) Stderr() io.Reader { return s.stderr }

func (s *fakeTerminalSession) Write(data []byte) (int, error) {
	s.writeCalls.Add(1)
	select {
	case <-s.closed:
		return 0, net.ErrClosed
	default:
		return len(data), nil
	}
}

func (s *fakeTerminalSession) Resize(int, int) error {
	s.resizeCalls.Add(1)
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
		return nil
	}
}

func (s *fakeTerminalSession) Wait() error {
	s.waitCalls.Add(1)
	select {
	case err := <-s.waitResult:
		return err
	case <-s.closed:
		return net.ErrClosed
	}
}

func (s *fakeTerminalSession) Close() error {
	s.closeOnce.Do(func() {
		s.closeCalls.Add(1)
		close(s.closed)
	})
	return nil
}

type fakeTerminalRead struct {
	message terminalClientMessage
	err     error
}

type fakeTerminalSocket struct {
	reads chan fakeTerminalRead

	closed    chan struct{}
	closeOnce sync.Once
	writesMu  sync.Mutex
	writes    []terminalServerMessage

	blockWrites  bool
	startedOnce  sync.Once
	writeStarted chan struct{}

	readLimit            atomic.Int64
	readDeadlineCount    atomic.Int32
	writeDeadlineCount   atomic.Int32
	closeCalls           atomic.Int32
	concurrentWriters    atomic.Int32
	maxConcurrentWriters atomic.Int32
}

func newFakeTerminalSocket() *fakeTerminalSocket {
	return &fakeTerminalSocket{
		reads:        make(chan fakeTerminalRead, terminalClientCapacity+1),
		closed:       make(chan struct{}),
		writeStarted: make(chan struct{}),
	}
}

func (s *fakeTerminalSocket) ReadJSON(value any) error {
	select {
	case read := <-s.reads:
		if read.err != nil {
			return read.err
		}
		message, ok := value.(*terminalClientMessage)
		if !ok {
			return errors.New("unexpected terminal read target")
		}
		*message = read.message
		return nil
	case <-s.closed:
		return net.ErrClosed
	}
}

func (s *fakeTerminalSocket) WriteJSON(value any) error {
	current := s.concurrentWriters.Add(1)
	defer s.concurrentWriters.Add(-1)
	for {
		maximum := s.maxConcurrentWriters.Load()
		if current <= maximum || s.maxConcurrentWriters.CompareAndSwap(maximum, current) {
			break
		}
	}
	s.startedOnce.Do(func() { close(s.writeStarted) })

	if s.blockWrites {
		<-s.closed
		return net.ErrClosed
	}
	message, ok := value.(terminalServerMessage)
	if !ok {
		return errors.New("unexpected terminal write value")
	}
	s.writesMu.Lock()
	s.writes = append(s.writes, message)
	s.writesMu.Unlock()
	return nil
}

func (s *fakeTerminalSocket) SetReadLimit(limit int64) {
	s.readLimit.Store(limit)
}

func (s *fakeTerminalSocket) SetReadDeadline(time.Time) error {
	s.readDeadlineCount.Add(1)
	return nil
}

func (s *fakeTerminalSocket) SetWriteDeadline(time.Time) error {
	s.writeDeadlineCount.Add(1)
	return nil
}

func (s *fakeTerminalSocket) Close() error {
	s.closeOnce.Do(func() {
		s.closeCalls.Add(1)
		close(s.closed)
	})
	return nil
}

func (s *fakeTerminalSocket) messages() []terminalServerMessage {
	s.writesMu.Lock()
	defer s.writesMu.Unlock()
	return append([]terminalServerMessage(nil), s.writes...)
}
