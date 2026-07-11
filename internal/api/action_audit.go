package api

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/PhantoNull/home-mesh/internal/store"
)

const actionAuditTimeout = 3 * time.Second

type auditedActionRecorder interface {
	AddAction(context.Context, store.Action) (store.Action, error)
	UpdateAction(context.Context, store.Action) (store.Action, error)
}

type actionHistoryStore interface {
	auditedActionRecorder
	ListActionsPage(context.Context, int, int) ([]store.Action, error)
	ClearActions(context.Context) error
}

type auditedOperationOutcome struct {
	Err           error
	Metadata      map[string]string
	ResultSummary string
	FinishedAt    time.Time
}

type auditedActionResult struct {
	Action        store.Action
	OperationErr  error
	FinalAuditErr error
}

func handleActionHistory(inventory actionHistoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			limit, err := parseBoundedQueryInt(r, "limit", 200, 1, 500)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			offset, err := parseBoundedQueryInt(r, "offset", 0, 0, 100_000)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			actionHistory, err := inventory.ListActionsPage(r.Context(), limit, offset)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load actions"})
				return
			}

			writeJSON(w, http.StatusOK, actionHistory)
		case http.MethodDelete:
			actionResult, err := executeAuditedAction(r.Context(), inventory, store.Action{
				ID:         generateActionID("clear_action_history"),
				ActionType: "clear_action_history",
			}, func() auditedOperationOutcome {
				clearErr := inventory.ClearActions(r.Context())
				if clearErr != nil {
					return auditedOperationOutcome{
						Err:           clearErr,
						ResultSummary: "Action history clear failed.",
						Metadata:      map[string]string{"terminationReason": "clear_error"},
					}
				}
				return auditedOperationOutcome{
					ResultSummary: "Action history cleared.",
					Metadata:      map[string]string{"terminationReason": "history_cleared"},
				}
			})
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start action history clear"})
				return
			}
			if actionResult.FinalAuditErr != nil {
				log.Printf("finalize action history clear %s: %v", actionResult.Action.ID, actionResult.FinalAuditErr)
			}
			if actionResult.OperationErr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear actions"})
				return
			}

			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, http.MethodGet, http.MethodDelete)
		}
	}
}

func executeAuditedAction(
	ctx context.Context,
	recorder auditedActionRecorder,
	action store.Action,
	operation func() auditedOperationOutcome,
) (auditedActionResult, error) {
	running, err := startAuditedAction(ctx, recorder, action)
	if err != nil {
		return auditedActionResult{}, err
	}

	outcome := operation()
	finished, auditErr := finishAuditedAction(ctx, recorder, running, outcome)
	return auditedActionResult{
		Action:        finished,
		OperationErr:  outcome.Err,
		FinalAuditErr: auditErr,
	}, nil
}

func startAuditedAction(ctx context.Context, recorder auditedActionRecorder, action store.Action) (store.Action, error) {
	action.Status = "running"
	action.ResultSummary = ""
	action.FinishedAt = time.Time{}
	action.Metadata = cloneActionMetadata(action.Metadata)
	if action.StartedAt.IsZero() {
		action.StartedAt = time.Now().UTC()
	}

	auditContext, cancel := context.WithTimeout(ctx, actionAuditTimeout)
	defer cancel()
	return recorder.AddAction(auditContext, action)
}

func finishAuditedAction(
	ctx context.Context,
	recorder auditedActionRecorder,
	action store.Action,
	outcome auditedOperationOutcome,
) (store.Action, error) {
	if outcome.Err == nil {
		action.Status = "completed"
		action.ResultSummary = "Action completed."
	} else {
		action.Status = "failed"
		action.ResultSummary = "Action failed."
	}
	if outcome.ResultSummary != "" {
		action.ResultSummary = outcome.ResultSummary
	}
	action.Metadata = mergeActionMetadata(action.Metadata, outcome.Metadata)
	action.FinishedAt = outcome.FinishedAt.UTC()
	if action.FinishedAt.IsZero() {
		action.FinishedAt = time.Now().UTC()
	}

	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), actionAuditTimeout)
	defer cancel()
	persisted, err := recorder.UpdateAction(auditContext, action)
	if err != nil {
		return action, err
	}
	return persisted, nil
}

func cloneActionMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(metadata))
	for key, value := range metadata {
		cloned[key] = value
	}
	return cloned
}

func mergeActionMetadata(base map[string]string, extra map[string]string) map[string]string {
	merged := cloneActionMetadata(base)
	for key, value := range extra {
		merged[key] = value
	}
	return merged
}
