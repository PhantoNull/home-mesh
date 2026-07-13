package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

const (
	terminalReadLimit          = 32 << 10
	terminalMaxInputBytes      = 16 << 10
	terminalMaxCols            = 500
	terminalMaxRows            = 200
	terminalOutputChunkBytes   = 4 << 10
	terminalOutboundCapacity   = 64
	terminalCommandCapacity    = 16
	terminalClientCapacity     = 16
	terminalReadTimeout        = 40 * time.Second
	terminalWriteTimeout       = 10 * time.Second
	terminalOutputDrainTimeout = 250 * time.Millisecond
	terminalFinalFlushTimeout  = 500 * time.Millisecond
)

var (
	errTerminalOutputBackpressure = errors.New("terminal output backpressure limit exceeded")
	errTerminalInputBackpressure  = errors.New("terminal input backpressure limit exceeded")
)

type terminalClientMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

type terminalServerMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
}

type terminalSession interface {
	Stdout() io.Reader
	Stderr() io.Reader
	Write([]byte) (int, error)
	Resize(int, int) error
	Wait() error
	Close() error
}

type terminalSocket interface {
	ReadJSON(any) error
	WriteJSON(any) error
	SetReadLimit(int64)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}

type terminalBridgeResult struct {
	Err               error
	TerminationReason string
	notifyClient      bool
	drainOutput       bool
}

type terminalWriteRequest struct {
	message terminalServerMessage
	written chan error
}

type terminalClientEvent struct {
	message terminalClientMessage
	err     error
}

type terminalSessionCommand struct {
	message terminalClientMessage
}

type terminalUTF8Decoder struct {
	carry []byte
}

type terminalBridge struct {
	ctx     context.Context
	cancel  context.CancelFunc
	socket  terminalSocket
	session terminalSession

	outbound       chan terminalWriteRequest
	clientEvents   chan terminalClientEvent
	sessionCommand chan terminalSessionCommand
	workerErrors   chan error
	waitDone       chan error
	writerDone     chan error

	workers           sync.WaitGroup
	outputMu          sync.Mutex
	outputReaders     int
	outputReadersDone chan struct{}
	outputSealed      bool
	stopSessionOnce   sync.Once
	closeSocketOnce   sync.Once
	shutdownOnce      sync.Once
}

func runTerminalBridge(ctx context.Context, socket terminalSocket, session terminalSession) terminalBridgeResult {
	bridgeContext, cancel := context.WithCancel(ctx)
	bridge := &terminalBridge{
		ctx:               bridgeContext,
		cancel:            cancel,
		socket:            socket,
		session:           session,
		outbound:          make(chan terminalWriteRequest, terminalOutboundCapacity),
		clientEvents:      make(chan terminalClientEvent, terminalClientCapacity),
		sessionCommand:    make(chan terminalSessionCommand, terminalCommandCapacity),
		workerErrors:      make(chan error, 1),
		waitDone:          make(chan error, 1),
		writerDone:        make(chan error, 1),
		outputReadersDone: make(chan struct{}),
	}
	defer func() {
		bridge.shutdown()
		bridge.workers.Wait()
	}()

	socket.SetReadLimit(terminalReadLimit)
	if err := socket.SetReadDeadline(time.Now().Add(terminalReadTimeout)); err != nil {
		return terminalBridgeResult{Err: fmt.Errorf("set terminal read deadline: %w", err), TerminationReason: "transport_error"}
	}

	bridge.startWorkers()
	if !bridge.tryEnqueue(terminalServerMessage{Type: "status", Data: "connected"}) {
		return terminalBridgeResult{Err: errTerminalOutputBackpressure, TerminationReason: "backpressure"}
	}

	result := bridge.coordinate()
	if result.drainOutput {
		bridge.drainSessionOutput()
	}
	bridge.stopSession()
	if result.notifyClient {
		messages := make([]terminalServerMessage, 0, 2)
		if result.Err != nil {
			messages = append(messages, terminalServerMessage{Type: "error", Data: result.Err.Error()})
		}
		messages = append(messages, terminalServerMessage{Type: "status", Data: "closed"})
		bridge.flushFinal(messages)
	}
	return result
}

func (b *terminalBridge) startWorkers() {
	readers := []io.Reader{b.session.Stdout(), b.session.Stderr()}
	b.outputMu.Lock()
	b.outputReaders = len(readers)
	if b.outputReaders == 0 {
		close(b.outputReadersDone)
	}
	b.outputMu.Unlock()

	b.workers.Add(1)
	go b.writeSocket()
	b.workers.Add(1)
	go b.readSocket()
	b.workers.Add(1)
	go b.writeSession()
	b.workers.Add(1)
	go b.waitSession()
	for _, reader := range readers {
		b.workers.Add(1)
		go b.readSessionOutput(reader)
	}
}

func (b *terminalBridge) coordinate() terminalBridgeResult {
	for {
		select {
		case <-b.ctx.Done():
			return terminalBridgeResult{Err: b.ctx.Err(), TerminationReason: "context_cancelled"}
		default:
		}
		select {
		case <-b.ctx.Done():
			return terminalBridgeResult{Err: b.ctx.Err(), TerminationReason: "context_cancelled"}
		case err := <-b.waitDone:
			if ctxErr := b.ctx.Err(); ctxErr != nil {
				return terminalBridgeResult{Err: ctxErr, TerminationReason: "context_cancelled"}
			}
			if isNormalTerminalWait(err) {
				return terminalBridgeResult{TerminationReason: "remote_exit", notifyClient: true, drainOutput: true}
			}
			return terminalBridgeResult{Err: fmt.Errorf("remote SSH session failed: %w", err), TerminationReason: "remote_error", notifyClient: true, drainOutput: true}
		case event := <-b.clientEvents:
			if ctxErr := b.ctx.Err(); ctxErr != nil {
				return terminalBridgeResult{Err: ctxErr, TerminationReason: "context_cancelled"}
			}
			if event.err != nil {
				if isNormalTerminalDisconnect(event.err) {
					return terminalBridgeResult{TerminationReason: "client_disconnect"}
				}
				return terminalBridgeResult{Err: fmt.Errorf("read terminal client message: %w", event.err), TerminationReason: "transport_error"}
			}
			if result := b.handleClientMessage(event.message); result != nil {
				return *result
			}
		case err := <-b.workerErrors:
			if ctxErr := b.ctx.Err(); ctxErr != nil {
				return terminalBridgeResult{Err: ctxErr, TerminationReason: "context_cancelled"}
			}
			reason := "ssh_io_error"
			if errors.Is(err, errTerminalOutputBackpressure) || errors.Is(err, errTerminalInputBackpressure) {
				reason = "backpressure"
			}
			return terminalBridgeResult{Err: err, TerminationReason: reason, notifyClient: true}
		case err := <-b.writerDone:
			if ctxErr := b.ctx.Err(); ctxErr != nil {
				return terminalBridgeResult{Err: ctxErr, TerminationReason: "context_cancelled"}
			}
			if isNormalTerminalDisconnect(err) {
				return terminalBridgeResult{TerminationReason: "client_disconnect"}
			}
			return terminalBridgeResult{Err: fmt.Errorf("write terminal client message: %w", err), TerminationReason: "transport_error"}
		}
	}
}

func (b *terminalBridge) handleClientMessage(message terminalClientMessage) *terminalBridgeResult {
	switch message.Type {
	case "input":
		if len([]byte(message.Data)) > terminalMaxInputBytes {
			return &terminalBridgeResult{Err: fmt.Errorf("terminal input exceeds %d bytes", terminalMaxInputBytes), TerminationReason: "protocol_error", notifyClient: true}
		}
		if !b.trySessionCommand(message) {
			return &terminalBridgeResult{Err: errTerminalInputBackpressure, TerminationReason: "backpressure", notifyClient: true}
		}
	case "resize":
		if message.Cols < 1 || message.Cols > terminalMaxCols || message.Rows < 1 || message.Rows > terminalMaxRows {
			return &terminalBridgeResult{Err: fmt.Errorf("terminal size must be within 1x1 and %dx%d", terminalMaxCols, terminalMaxRows), TerminationReason: "protocol_error", notifyClient: true}
		}
		if !b.trySessionCommand(message) {
			return &terminalBridgeResult{Err: errTerminalInputBackpressure, TerminationReason: "backpressure", notifyClient: true}
		}
	case "ping":
		if !b.tryEnqueue(terminalServerMessage{Type: "pong"}) {
			return &terminalBridgeResult{Err: errTerminalOutputBackpressure, TerminationReason: "backpressure", notifyClient: true}
		}
	case "close":
		return &terminalBridgeResult{TerminationReason: "client_close", notifyClient: true}
	default:
		return &terminalBridgeResult{Err: fmt.Errorf("unsupported terminal message type %q", message.Type), TerminationReason: "protocol_error", notifyClient: true}
	}
	return nil
}

func (b *terminalBridge) readSocket() {
	defer b.workers.Done()
	for {
		var message terminalClientMessage
		if err := b.socket.ReadJSON(&message); err != nil {
			b.sendClientEvent(terminalClientEvent{err: err})
			return
		}
		if err := b.socket.SetReadDeadline(time.Now().Add(terminalReadTimeout)); err != nil {
			b.sendClientEvent(terminalClientEvent{err: err})
			return
		}
		if !b.sendClientEvent(terminalClientEvent{message: message}) {
			return
		}
	}
}

func (b *terminalBridge) sendClientEvent(event terminalClientEvent) bool {
	select {
	case b.clientEvents <- event:
		return true
	case <-b.ctx.Done():
		return false
	}
}

func (b *terminalBridge) writeSocket() {
	defer b.workers.Done()
	var loopErr error
	defer func() {
		select {
		case b.writerDone <- loopErr:
		default:
		}
	}()

	for {
		select {
		case <-b.ctx.Done():
			loopErr = b.ctx.Err()
			return
		case request := <-b.outbound:
			if err := b.socket.SetWriteDeadline(time.Now().Add(terminalWriteTimeout)); err != nil {
				loopErr = err
				completeTerminalWrite(request, err)
				return
			}
			err := b.socket.WriteJSON(request.message)
			completeTerminalWrite(request, err)
			if err != nil {
				loopErr = err
				return
			}
		}
	}
}

func completeTerminalWrite(request terminalWriteRequest, err error) {
	if request.written == nil {
		return
	}
	select {
	case request.written <- err:
	default:
	}
}

func (b *terminalBridge) readSessionOutput(reader io.Reader) {
	defer b.workers.Done()
	defer b.finishOutputReader()
	buffer := make([]byte, terminalOutputChunkBytes)
	decoder := terminalUTF8Decoder{}
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			output := decoder.Decode(buffer[:n], false)
			if output != "" && !b.tryEnqueueOutput(output) {
				return
			}
		}
		if err != nil {
			if output := decoder.Decode(nil, true); output != "" && !b.tryEnqueueOutput(output) {
				return
			}
			if !errors.Is(err, io.EOF) && b.ctx.Err() == nil {
				b.reportWorkerError(fmt.Errorf("read SSH terminal output: %w", err))
			}
			return
		}
	}
}

func (b *terminalBridge) tryEnqueueOutput(output string) bool {
	b.outputMu.Lock()
	defer b.outputMu.Unlock()
	if b.outputSealed {
		return false
	}
	if b.tryEnqueue(terminalServerMessage{Type: "output", Data: output}) {
		return true
	}
	if b.ctx.Err() == nil {
		b.reportWorkerError(errTerminalOutputBackpressure)
	}
	return false
}

func (b *terminalBridge) finishOutputReader() {
	b.outputMu.Lock()
	defer b.outputMu.Unlock()
	b.outputReaders--
	if b.outputReaders == 0 {
		close(b.outputReadersDone)
	}
}

func (b *terminalBridge) drainSessionOutput() {
	timer := time.NewTimer(terminalOutputDrainTimeout)
	defer timer.Stop()
	select {
	case <-b.outputReadersDone:
	case <-timer.C:
	}

	// Enqueue and seal share this mutex so late readers cannot write behind the final status.
	b.outputMu.Lock()
	b.outputSealed = true
	b.outputMu.Unlock()
}

func (d *terminalUTF8Decoder) Decode(chunk []byte, final bool) string {
	data := make([]byte, 0, len(d.carry)+len(chunk))
	data = append(data, d.carry...)
	data = append(data, chunk...)
	d.carry = d.carry[:0]

	var output strings.Builder
	for len(data) > 0 {
		if !final && !utf8.FullRune(data) {
			d.carry = append(d.carry, data...)
			break
		}
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			output.WriteRune(utf8.RuneError)
			data = data[1:]
			continue
		}
		output.Write(data[:size])
		data = data[size:]
	}
	return output.String()
}

func (b *terminalBridge) writeSession() {
	defer b.workers.Done()
	for {
		select {
		case <-b.ctx.Done():
			return
		case command := <-b.sessionCommand:
			var err error
			switch command.message.Type {
			case "input":
				_, err = b.session.Write([]byte(command.message.Data))
			case "resize":
				err = b.session.Resize(command.message.Cols, command.message.Rows)
			}
			if err != nil {
				b.reportWorkerError(fmt.Errorf("write SSH terminal: %w", err))
				return
			}
		}
	}
}

func (b *terminalBridge) waitSession() {
	defer b.workers.Done()
	err := b.session.Wait()
	select {
	case b.waitDone <- err:
	case <-b.ctx.Done():
	}
}

func (b *terminalBridge) tryEnqueue(message terminalServerMessage) bool {
	select {
	case <-b.ctx.Done():
		return false
	default:
	}
	select {
	case b.outbound <- terminalWriteRequest{message: message}:
		return true
	default:
		return false
	}
}

func (b *terminalBridge) trySessionCommand(message terminalClientMessage) bool {
	select {
	case <-b.ctx.Done():
		return false
	default:
	}
	select {
	case b.sessionCommand <- terminalSessionCommand{message: message}:
		return true
	default:
		return false
	}
}

func (b *terminalBridge) reportWorkerError(err error) {
	select {
	case b.workerErrors <- err:
	default:
	}
}

func (b *terminalBridge) flushFinal(messages []terminalServerMessage) {
	timer := time.NewTimer(terminalFinalFlushTimeout)
	defer timer.Stop()
	for _, message := range messages {
		written := make(chan error, 1)
		request := terminalWriteRequest{message: message, written: written}
		select {
		case b.outbound <- request:
		case <-b.ctx.Done():
			return
		case <-timer.C:
			return
		}
		select {
		case err := <-written:
			if err != nil {
				return
			}
		case <-b.ctx.Done():
			return
		case <-timer.C:
			return
		}
	}
}

func (b *terminalBridge) stopSession() {
	b.stopSessionOnce.Do(func() {
		_ = b.session.Close()
	})
}

func (b *terminalBridge) closeSocket() {
	b.closeSocketOnce.Do(func() {
		_ = b.socket.Close()
	})
}

func (b *terminalBridge) shutdown() {
	b.shutdownOnce.Do(func() {
		b.cancel()
		b.closeSocket()
		b.stopSession()
	})
}

func isNormalTerminalWait(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "closed")
}

func isNormalTerminalDisconnect(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	return websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived)
}
