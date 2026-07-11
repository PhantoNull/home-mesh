package monitor

import (
	"errors"
	"testing"
)

func TestEventBusAssignsMonotonicCursorsAndReplays(t *testing.T) {
	t.Parallel()

	bus := NewEventBusWithOptions(EventBusOptions{Generation: "test-generation", HistoryCapacity: 4})
	first := bus.Publish(ScanEvent{Kind: EventScanStarted, Data: []byte(`{"scan":1}`)})
	second := bus.Publish(ScanEvent{Kind: EventScanComplete, Data: []byte(`{"scan":1}`)})
	if first.ID != 1 || second.ID != 2 {
		t.Fatalf("IDs = %d, %d; want 1, 2", first.ID, second.ID)
	}
	if first.Cursor() != "test-generation:1" {
		t.Fatalf("cursor = %q", first.Cursor())
	}

	id, events, err := bus.SubscribeFrom(first.Cursor())
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Unsubscribe(id)
	replayed := <-events
	if replayed.ID != second.ID || replayed.Kind != second.Kind {
		t.Fatalf("replayed event = %#v, want second event", replayed)
	}
}

func TestEventBusRejectsExpiredAndForeignCursors(t *testing.T) {
	t.Parallel()

	bus := NewEventBusWithOptions(EventBusOptions{Generation: "current", HistoryCapacity: 2})
	first := bus.Publish(ScanEvent{Kind: EventScanStarted})
	bus.Publish(ScanEvent{Kind: EventDeviceUpdate})
	bus.Publish(ScanEvent{Kind: EventScanComplete})
	bus.Publish(ScanEvent{Kind: EventNodeUpdate})

	if _, _, err := bus.SubscribeFrom(first.Cursor()); !errors.Is(err, ErrEventHistoryExpired) {
		t.Fatalf("expired cursor error = %v", err)
	}
	if _, _, err := bus.SubscribeFrom("previous:2"); !errors.Is(err, ErrEventGenerationChange) {
		t.Fatalf("foreign cursor error = %v", err)
	}
}

func TestEventBusDisconnectsSlowSubscriberAndSupportsRecovery(t *testing.T) {
	t.Parallel()

	bus := NewEventBusWithOptions(EventBusOptions{
		Generation: "overflow", HistoryCapacity: 4, SubscriberBuffer: 1,
	})
	id, events := bus.Subscribe()
	first := bus.Publish(ScanEvent{Kind: EventScanStarted})
	second := bus.Publish(ScanEvent{Kind: EventDeviceUpdate})

	received, ok := <-events
	if !ok || received.ID != first.ID {
		t.Fatalf("first receive = %#v, %t", received, ok)
	}
	if _, ok := <-events; ok {
		t.Fatal("slow subscriber channel remained open")
	}
	bus.Unsubscribe(id)

	replayID, replay, err := bus.SubscribeFrom(first.Cursor())
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Unsubscribe(replayID)
	if recovered := <-replay; recovered.ID != second.ID {
		t.Fatalf("recovered ID = %d, want %d", recovered.ID, second.ID)
	}
}

func TestEventBusCopiesPublishedData(t *testing.T) {
	t.Parallel()

	bus := NewEventBusWithOptions(EventBusOptions{Generation: "copy"})
	id, events := bus.Subscribe()
	defer bus.Unsubscribe(id)
	payload := []byte(`{"value":"before"}`)
	published := bus.Publish(ScanEvent{Kind: EventDeviceUpdate, Data: payload})
	payload[10] = 'X'

	if string(published.Data) != `{"value":"before"}` {
		t.Fatalf("published data = %s", published.Data)
	}
	if received := <-events; string(received.Data) != `{"value":"before"}` {
		t.Fatalf("received data = %s", received.Data)
	}
}
