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

		flusher, ok := w.(http.Flusher)
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming not supported"})
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no") // disable nginx proxy buffering

		id, events := bus.Subscribe()
		defer bus.Unsubscribe(id)

		fmt.Fprintf(w, ": connected\n\n")
		flusher.Flush()

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
				writeSSEEvent(w, event)
				flusher.Flush()

			case <-heartbeat.C:
				fmt.Fprintf(w, ": heartbeat\n\n")
				flusher.Flush()
			}
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, event monitor.ScanEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: scan\ndata: %s\n\n", data)
}
