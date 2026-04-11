package monitor

import (
	"encoding/json"
	"sync"
)

// ScanEventKind labels the type of event pushed over SSE.
type ScanEventKind = string

const (
	EventScanStarted  ScanEventKind = "scan-started"
	EventScanComplete ScanEventKind = "scan-complete"
	EventDeviceUpdate ScanEventKind = "device-updated"
	EventNodeUpdate   ScanEventKind = "node-updated"
)

// ScanEvent is what the SSE handler serialises and sends to the browser.
type ScanEvent struct {
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

// EventBus is a simple fan-out pub/sub channel. All methods are safe for
// concurrent use from multiple goroutines.
type EventBus struct {
	mu   sync.Mutex
	subs map[uint64]chan ScanEvent
	next uint64
}

func NewEventBus() *EventBus {
	return &EventBus{subs: make(map[uint64]chan ScanEvent)}
}

// Subscribe registers a new consumer and returns its ID plus a receive channel.
// The channel is buffered so that a slow consumer doesn't block the publisher.
func (b *EventBus) Subscribe() (uint64, <-chan ScanEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	ch := make(chan ScanEvent, 64)
	b.subs[id] = ch
	return id, ch
}

// Unsubscribe removes and closes the channel for the given subscriber ID.
func (b *EventBus) Unsubscribe(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.subs[id]; ok {
		delete(b.subs, id)
		close(ch)
	}
}

// Publish sends an event to all current subscribers. If a subscriber's channel
// buffer is full, that event is dropped for that subscriber.
func (b *EventBus) Publish(event ScanEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		select {
		case ch <- event:
		default:
		}
	}
}

// publishJSON is a helper that marshals data and calls Publish.
func (b *EventBus) publishJSON(kind ScanEventKind, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	b.Publish(ScanEvent{Kind: kind, Data: raw})
}
