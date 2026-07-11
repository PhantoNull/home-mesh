package api

import (
	"context"
	"time"

	"github.com/PhantoNull/home-mesh/internal/store"
)

const actionAuditTimeout = 3 * time.Second

type auditedActionRecorder interface {
	AddAction(context.Context, store.Action) (store.Action, error)
	UpdateAction(context.Context, store.Action) (store.Action, error)
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
