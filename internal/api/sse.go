package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/PhantoNull/home-mesh/internal/monitor"
)

const sseHeartbeatInterval = 25 * time.Second

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

		id, events := bus.Subscribe()
		defer bus.Unsubscribe(id)

		if err := writeSSEComment(w, "connected"); err != nil {
			return
		}
		if err := flushSSE(w); err != nil {
			return
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
	return writeSSEJSONEvent(w, "scan", event)
}

func writeSSEJSONEvent(w http.ResponseWriter, eventName string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventName, data)
	return err
}

func writeSSEComment(w http.ResponseWriter, comment string) error {
	_, err := fmt.Fprintf(w, ": %s\n\n", comment)
	return err
}

func flushSSE(w http.ResponseWriter) error {
	return http.NewResponseController(w).Flush()
}
