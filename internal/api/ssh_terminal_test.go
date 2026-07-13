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

func TestTerminalBridgeDrainsRemoteOutputBeforeClosed(t *testing.T) {
	releaseStdout := make(chan struct{})
	releaseStderr := make(chan struct{})
	stdout := newDelayedTerminalReader("final stdout", releaseStdout)
	stderr := newDelayedTerminalReader("final stderr", releaseStderr)
	session := newFakeTerminalSession(stdout, stderr)
	socket := newFakeTerminalSocket()
	resultDone := runTerminalBridgeAsync(context.Background(), socket, session)

	for name, started := range map[string]<-chan struct{}{
		"stdout": stdout.started,
		"stderr": stderr.started,
	} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("terminal %s reader did not start", name)
		}
	}
	go func() {
		<-session.waitReturned
		time.Sleep(50 * time.Millisecond)
		close(releaseStdout)
		time.Sleep(50 * time.Millisecond)
		close(releaseStderr)
	}()
	session.waitResult <- nil

	result := awaitTerminalResult(t, resultDone)
	if result.Err != nil || result.TerminationReason != "remote_exit" {
		t.Fatalf("result = %+v, want clean remote exit", result)
	}
	messages := socket.messages()
	closed := terminalServerMessage{Type: "status", Data: "closed"}
	assertTerminalMessageBefore(t, messages, terminalServerMessage{Type: "status", Data: "connected"}, closed)
	assertTerminalMessageBefore(t, messages, terminalServerMessage{Type: "output", Data: "final stdout"}, closed)
	assertTerminalMessageBefore(t, messages, terminalServerMessage{Type: "output", Data: "final stderr"}, closed)
}

func TestTerminalBridgeBoundsOutputDrainWhenReaderWaitsForClose(t *testing.T) {
	session := newFakeTerminalSession(bytes.NewReader(nil), bytes.NewReader(nil))
	stdout := newCloseAwareTerminalReader(session.closed)
	session.stdout = stdout
	socket := newFakeTerminalSocket()
	resultDone := runTerminalBridgeAsync(context.Background(), socket, session)

	select {
	case <-stdout.started:
	case <-time.After(time.Second):
		t.Fatal("terminal stdout reader did not start")
	}
	startedAt := time.Now()
	session.waitResult <- nil

	result := awaitTerminalResult(t, resultDone)
	if result.Err != nil || result.TerminationReason != "remote_exit" {
		t.Fatalf("result = %+v, want clean remote exit", result)
	}
	elapsed := time.Since(startedAt)
	if elapsed < terminalOutputDrainTimeout/2 {
		t.Fatalf("terminal bridge skipped bounded output drain: stopped after %s", elapsed)
	}
	if elapsed > terminalOutputDrainTimeout+time.Second {
		t.Fatalf("terminal bridge exceeded bounded output drain: stopped after %s", elapsed)
	}
	select {
	case <-stdout.returned:
	default:
		t.Fatal("terminal stdout reader remained blocked after bridge shutdown")
	}
	assertTerminalMessage(t, socket.messages(), terminalServerMessage{Type: "status", Data: "closed"})
}

func TestTerminalBridgeDrainsOutputBeforeRemoteErrorAndClosed(t *testing.T) {
	releaseStderr := make(chan struct{})
	stderr := newDelayedTerminalReader("remote failure detail", releaseStderr)
	session := newFakeTerminalSession(bytes.NewReader(nil), stderr)
	socket := newFakeTerminalSocket()
	resultDone := runTerminalBridgeAsync(context.Background(), socket, session)

	select {
	case <-stderr.started:
	case <-time.After(time.Second):
		t.Fatal("terminal stderr reader did not start")
	}
	go func() {
		<-session.waitReturned
		time.Sleep(50 * time.Millisecond)
		close(releaseStderr)
	}()
	waitErr := errors.New("exit status 1")
	session.waitResult <- waitErr

	result := awaitTerminalResult(t, resultDone)
	if !errors.Is(result.Err, waitErr) || result.TerminationReason != "remote_error" {
		t.Fatalf("result = %+v, want remote error", result)
	}
	messages := socket.messages()
	output := terminalServerMessage{Type: "output", Data: "remote failure detail"}
	errorMessage := terminalServerMessage{Type: "error", Data: "remote SSH session failed: exit status 1"}
	closed := terminalServerMessage{Type: "status", Data: "closed"}
	assertTerminalMessageBefore(t, messages, output, errorMessage)
	assertTerminalMessageBefore(t, messages, errorMessage, closed)
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

func TestTerminalUTF8DecoderCarriesSplitRunes(t *testing.T) {
	decoder := terminalUTF8Decoder{}
	euro := []byte("EUR: \u20ac")
	if got := decoder.Decode(euro[:6], false); got != "EUR: " {
		t.Fatalf("first chunk = %q", got)
	}
	if got := decoder.Decode(euro[6:7], false); got != "" {
		t.Fatalf("incomplete chunk = %q", got)
	}
	if got := decoder.Decode(euro[7:], false); got != "\u20ac" {
		t.Fatalf("completed rune = %q", got)
	}
	if got := decoder.Decode([]byte{0xff}, true); got != "\ufffd" {
		t.Fatalf("invalid byte = %q", got)
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

func assertTerminalMessageBefore(t *testing.T, messages []terminalServerMessage, before terminalServerMessage, after terminalServerMessage) {
	t.Helper()
	beforeIndex := -1
	afterIndex := -1
	for index, message := range messages {
		if beforeIndex == -1 && message == before {
			beforeIndex = index
		}
		if afterIndex == -1 && message == after {
			afterIndex = index
		}
	}
	if beforeIndex == -1 || afterIndex == -1 || beforeIndex >= afterIndex {
		t.Fatalf("messages = %+v, want %+v before %+v", messages, before, after)
	}
}

type closeAwareTerminalReader struct {
	closed       <-chan struct{}
	started      chan struct{}
	returned     chan struct{}
	startedOnce  sync.Once
	returnedOnce sync.Once
}

func newCloseAwareTerminalReader(closed <-chan struct{}) *closeAwareTerminalReader {
	return &closeAwareTerminalReader{
		closed:   closed,
		started:  make(chan struct{}),
		returned: make(chan struct{}),
	}
}

func (r *closeAwareTerminalReader) Read([]byte) (int, error) {
	r.startedOnce.Do(func() { close(r.started) })
	<-r.closed
	r.returnedOnce.Do(func() { close(r.returned) })
	return 0, io.EOF
}

type delayedTerminalReader struct {
	data        []byte
	release     <-chan struct{}
	started     chan struct{}
	startedOnce sync.Once
	sent        bool
}

func newDelayedTerminalReader(data string, release <-chan struct{}) *delayedTerminalReader {
	return &delayedTerminalReader{
		data:    []byte(data),
		release: release,
		started: make(chan struct{}),
	}
}

func (r *delayedTerminalReader) Read(buffer []byte) (int, error) {
	r.startedOnce.Do(func() { close(r.started) })
	<-r.release
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	return copy(buffer, r.data), nil
}

type fakeTerminalSession struct {
	stdout io.Reader
	stderr io.Reader

	waitResult     chan error
	waitReturned   chan struct{}
	closed         chan struct{}
	closeOnce      sync.Once
	waitReturnOnce sync.Once

	waitCalls   atomic.Int32
	closeCalls  atomic.Int32
	writeCalls  atomic.Int32
	resizeCalls atomic.Int32
}

func newFakeTerminalSession(stdout io.Reader, stderr io.Reader) *fakeTerminalSession {
	return &fakeTerminalSession{
		stdout:       stdout,
		stderr:       stderr,
		waitResult:   make(chan error, 1),
		waitReturned: make(chan struct{}),
		closed:       make(chan struct{}),
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
		s.waitReturnOnce.Do(func() { close(s.waitReturned) })
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
