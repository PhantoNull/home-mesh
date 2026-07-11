package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/PhantoNull/home-mesh/internal/monitor"
)

const (
	sseHeartbeatInterval = 25 * time.Second
	sseWriteTimeout      = 10 * time.Second
)

func handleSSE(bus *monitor.EventBus) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}

		_, ok := w.(http.Flusher)
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming not supported"})
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no") // disable nginx proxy buffering

		id, events, replayErr := bus.SubscribeFrom(r.Header.Get("Last-Event-ID"))
		resetStream := false
		if replayErr != nil {
			if !errors.Is(replayErr, monitor.ErrEventCursorInvalid) &&
				!errors.Is(replayErr, monitor.ErrEventHistoryExpired) &&
				!errors.Is(replayErr, monitor.ErrEventGenerationChange) {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to subscribe to event stream"})
				return
			}
			id, events = bus.Subscribe()
			resetStream = true
		}
		defer bus.Unsubscribe(id)

		if err := writeSSEComment(w, "connected"); err != nil {
			return
		}
		if err := flushSSE(w); err != nil {
			return
		}
		if resetStream {
			resetData, _ := json.Marshal(map[string]string{"reason": "history-unavailable"})
			if err := writeSSEEvent(w, monitor.ScanEvent{Kind: monitor.EventStreamReset, Data: resetData}); err != nil {
				return
			}
			if err := flushSSE(w); err != nil {
				return
			}
		}

		heartbeat := time.NewTicker(sseHeartbeatInterval)
		defer heartbeat.Stop()

		for {
			select {
			case <-r.Context().Done():
				return

			case event, ok := <-events:
				if !ok {
					return
				}
				if err := writeSSEEvent(w, event); err != nil {
					return
				}
				if err := flushSSE(w); err != nil {
					return
				}

			case <-heartbeat.C:
				if err := writeSSEComment(w, "heartbeat"); err != nil {
					return
				}
				if err := flushSSE(w); err != nil {
					return
				}
			}
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, event monitor.ScanEvent) error {
	if err := setSSEWriteDeadline(w); err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if cursor := event.Cursor(); cursor != "" {
		if _, err := fmt.Fprintf(w, "id: %s\n", cursor); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "event: scan\ndata: %s\n\n", data)
	return err
}

func writeSSEJSONEvent(w http.ResponseWriter, eventName string, payload any) error {
	if err := setSSEWriteDeadline(w); err != nil {
		return err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventName, data)
	return err
}

func writeSSEComment(w http.ResponseWriter, comment string) error {
	if err := setSSEWriteDeadline(w); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, ": %s\n\n", comment)
	return err
}

func flushSSE(w http.ResponseWriter) error {
	controller := http.NewResponseController(w)
	err := controller.Flush()
	clearErr := controller.SetWriteDeadline(time.Time{})
	if errors.Is(clearErr, http.ErrNotSupported) {
		clearErr = nil
	}
	if err != nil {
		return err
	}
	return clearErr
}

func setSSEWriteDeadline(w http.ResponseWriter) error {
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(sseWriteTimeout))
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}
