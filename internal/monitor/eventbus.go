package monitor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanEventKind = string

const (
	EventScanStarted  ScanEventKind = "scan-started"
	EventScanComplete ScanEventKind = "scan-complete"
	EventDeviceUpdate ScanEventKind = "device-updated"
	EventNodeUpdate   ScanEventKind = "node-updated"
	EventStreamReset  ScanEventKind = "stream-reset"
)

var (
	ErrEventCursorInvalid    = errors.New("invalid event cursor")
	ErrEventHistoryExpired   = errors.New("event history expired")
	ErrEventGenerationChange = errors.New("event generation changed")
)

const (
	defaultEventHistoryCapacity = 512
	defaultSubscriberBuffer     = 128
)

type ScanEvent struct {
	Generation string          `json:"generation"`
	ID         uint64          `json:"id"`
	Kind       string          `json:"kind"`
	Data       json.RawMessage `json:"data"`
}

func (e ScanEvent) Cursor() string {
	if e.Generation == "" || e.ID == 0 {
		return ""
	}
	return e.Generation + ":" + strconv.FormatUint(e.ID, 10)
}

type EventBusOptions struct {
	HistoryCapacity  int
	SubscriberBuffer int
	Generation       string
}

type EventBus struct {
	mu               sync.Mutex
	subs             map[uint64]chan ScanEvent
	nextSubscriberID uint64
	nextEventID      uint64
	generation       string
	history          []ScanEvent
	historyCapacity  int
	subscriberBuffer int
}

func NewEventBus() *EventBus {
	return NewEventBusWithOptions(EventBusOptions{})
}

func NewEventBusWithOptions(options EventBusOptions) *EventBus {
	historyCapacity := options.HistoryCapacity
	if historyCapacity <= 0 {
		historyCapacity = defaultEventHistoryCapacity
	}
	subscriberBuffer := options.SubscriberBuffer
	if subscriberBuffer <= 0 {
		subscriberBuffer = defaultSubscriberBuffer
	}
	generation := strings.TrimSpace(options.Generation)
	if generation == "" {
		generation = newEventGeneration()
	}
	return &EventBus{
		subs:             make(map[uint64]chan ScanEvent),
		nextEventID:      1,
		generation:       generation,
		historyCapacity:  historyCapacity,
		subscriberBuffer: subscriberBuffer,
		history:          make([]ScanEvent, 0, historyCapacity),
	}
}

func newEventGeneration() string {
	var bytes [12]byte
	if _, err := rand.Read(bytes[:]); err == nil {
		return hex.EncodeToString(bytes[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

// Subscribe registers for events published after this call. Reconnecting SSE
// clients should use SubscribeFrom so the bounded history can fill any gap.
func (b *EventBus) Subscribe() (uint64, <-chan ScanEvent) {
	id, events, err := b.SubscribeFrom("")
	if err != nil {
		panic(fmt.Sprintf("subscribe without cursor: %v", err))
	}
	return id, events
}

// SubscribeFrom atomically replays every retained event after lastEventID and
// registers the live subscriber. The cursor format is "generation:id".
func (b *EventBus) SubscribeFrom(lastEventID string) (uint64, <-chan ScanEvent, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	afterID, err := b.validateCursorLocked(lastEventID)
	if err != nil {
		return 0, nil, err
	}
	replay := b.eventsAfterLocked(afterID)
	bufferSize := max(b.subscriberBuffer, len(replay)+b.subscriberBuffer)
	channel := make(chan ScanEvent, bufferSize)
	for _, event := range replay {
		channel <- cloneScanEvent(event)
	}
	id := b.nextSubscriberID
	b.nextSubscriberID++
	b.subs[id] = channel
	return id, channel, nil
}

func (b *EventBus) validateCursorLocked(cursor string) (uint64, error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return b.nextEventID - 1, nil
	}
	generation, idText, found := strings.Cut(cursor, ":")
	if !found || generation == "" || idText == "" {
		return 0, ErrEventCursorInvalid
	}
	if generation != b.generation {
		return 0, ErrEventGenerationChange
	}
	id, err := strconv.ParseUint(idText, 10, 64)
	if err != nil || id == 0 || id >= b.nextEventID {
		return 0, ErrEventCursorInvalid
	}
	if len(b.history) == 0 {
		return 0, ErrEventHistoryExpired
	}
	oldestID := b.history[0].ID
	if id < oldestID-1 {
		return 0, ErrEventHistoryExpired
	}
	return id, nil
}

func (b *EventBus) eventsAfterLocked(afterID uint64) []ScanEvent {
	if len(b.history) == 0 || afterID >= b.history[len(b.history)-1].ID {
		return nil
	}
	start := 0
	for start < len(b.history) && b.history[start].ID <= afterID {
		start++
	}
	return b.history[start:]
}

func (b *EventBus) Unsubscribe(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if channel, ok := b.subs[id]; ok {
		delete(b.subs, id)
		close(channel)
	}
}

// Publish assigns a stable cursor, stores the event in bounded history and
// fans it out. A subscriber whose buffer is full is disconnected, never
// silently skipped; it can replay from its last received cursor.
func (b *EventBus) Publish(event ScanEvent) ScanEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	event.Generation = b.generation
	event.ID = b.nextEventID
	b.nextEventID++
	event = cloneScanEvent(event)
	b.appendHistoryLocked(event)
	for id, channel := range b.subs {
		select {
		case channel <- cloneScanEvent(event):
		default:
			delete(b.subs, id)
			close(channel)
		}
	}
	return cloneScanEvent(event)
}

func (b *EventBus) appendHistoryLocked(event ScanEvent) {
	if len(b.history) == b.historyCapacity {
		copy(b.history, b.history[1:])
		b.history[len(b.history)-1] = event
		return
	}
	b.history = append(b.history, event)
}

func cloneScanEvent(event ScanEvent) ScanEvent {
	event.Data = append(json.RawMessage(nil), event.Data...)
	return event
}

func (b *EventBus) publishJSON(kind ScanEventKind, data any) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	b.Publish(ScanEvent{Kind: kind, Data: raw})
}
