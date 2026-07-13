package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/PhantoNull/home-mesh/internal/store"
)

func setVersionETag(w http.ResponseWriter, version int64) {
	if version > 0 {
		w.Header().Set("ETag", formatVersionETag(version))
	}
}

func formatVersionETag(version int64) string {
	return `"` + strconv.FormatInt(version, 10) + `"`
}

func requireIfMatchVersion(w http.ResponseWriter, r *http.Request) (int64, bool) {
	version, err := parseIfMatchVersion(r.Header.Values("If-Match"))
	if err != nil {
		writeJSON(w, http.StatusPreconditionRequired, map[string]string{
			"error": "If-Match must contain one strong ETag with a positive resource version",
		})
		return 0, false
	}
	return version, true
}

func parseIfMatchVersion(values []string) (int64, error) {
	if len(values) != 1 {
		return 0, errors.New("If-Match must be present exactly once")
	}

	value := strings.TrimSpace(values[0])
	if len(value) < 3 || strings.Contains(value, ",") || strings.HasPrefix(value, "W/") || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, errors.New("If-Match must be a single strong ETag")
	}

	rawVersion := value[1 : len(value)-1]
	version, err := strconv.ParseInt(rawVersion, 10, 64)
	if err != nil || version < 1 || rawVersion != strconv.FormatInt(version, 10) {
		return 0, errors.New("If-Match ETag must contain a positive canonical version")
	}
	return version, nil
}

func handlePreconditionError(w http.ResponseWriter, err error, message string) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusPreconditionFailed, map[string]string{"error": "resource version no longer matches"})
	case errors.Is(err, store.ErrValidation):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		return handleStoreError(w, err, message)
	}
	return true
}
