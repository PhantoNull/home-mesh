package api

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhantoNull/home-mesh/internal/store"
)

func TestExecuteAuditedActionDoesNotRunOperationWhenInitialAuditFails(t *testing.T) {
	t.Parallel()

	addErr := errors.New("insert audit")
	recorder := &fakeAuditedActionRecorder{addErr: addErr}
	var operationCalls atomic.Int32

	result, err := executeAuditedAction(context.Background(), recorder, store.Action{
		ID:         "action-1",
		ActionType: "wake_on_lan",
		Status:     "completed",
		FinishedAt: time.Now(),
	}, func() auditedOperationOutcome {
		operationCalls.Add(1)
		return auditedOperationOutcome{}
	})

	if !errors.Is(err, addErr) {
		t.Fatalf("execute audited action error = %v, want %v", err, addErr)
	}
	if operationCalls.Load() != 0 {
		t.Fatalf("operation calls = %d, want 0", operationCalls.Load())
	}
	if recorder.addCalls.Load() != 1 {
		t.Fatalf("AddAction calls = %d, want 1", recorder.addCalls.Load())
	}
	if recorder.updateCalls.Load() != 0 {
		t.Fatalf("UpdateAction calls = %d, want 0", recorder.updateCalls.Load())
	}
	if result.Action.ID != "" || result.OperationErr != nil || result.FinalAuditErr != nil {
		t.Fatalf("result = %+v, want zero value", result)
	}
	if recorder.added.Status != "running" {
		t.Fatalf("initial action status = %q, want running", recorder.added.Status)
	}
	if !recorder.added.FinishedAt.IsZero() {
		t.Fatalf("initial FinishedAt = %s, want zero", recorder.added.FinishedAt)
	}
}

func TestExecuteAuditedActionKeepsOperationSuccessWhenFinalAuditFails(t *testing.T) {
	t.Parallel()

	updateErr := errors.New("update audit")
	recorder := &fakeAuditedActionRecorder{updateErr: updateErr}
	var operationCalls atomic.Int32

	result, err := executeAuditedAction(context.Background(), recorder, store.Action{
		ID:         "action-2",
		ActionType: "ssh_command",
		Metadata:   map[string]string{"deviceName": "nas"},
	}, func() auditedOperationOutcome {
		operationCalls.Add(1)
		return auditedOperationOutcome{
			ResultSummary: "SSH command completed.",
			Metadata:      map[string]string{"terminationReason": "completed"},
		}
	})

	if err != nil {
		t.Fatalf("execute audited action: %v", err)
	}
	if operationCalls.Load() != 1 {
		t.Fatalf("operation calls = %d, want 1", operationCalls.Load())
	}
	if result.OperationErr != nil {
		t.Fatalf("operation error = %v, want nil", result.OperationErr)
	}
	if !errors.Is(result.FinalAuditErr, updateErr) {
		t.Fatalf("final audit error = %v, want %v", result.FinalAuditErr, updateErr)
	}
	if result.Action.Status != "completed" {
		t.Fatalf("action status = %q, want completed", result.Action.Status)
	}
	if result.Action.ResultSummary != "SSH command completed." {
		t.Fatalf("result summary = %q", result.Action.ResultSummary)
	}
	if result.Action.Metadata["terminationReason"] != "completed" {
		t.Fatalf("metadata = %v", result.Action.Metadata)
	}
	if recorder.updateCalls.Load() != 1 {
		t.Fatalf("UpdateAction calls = %d, want 1", recorder.updateCalls.Load())
	}
}

func TestFinishAuditedActionUsesDetachedBoundedContext(t *testing.T) {
	t.Parallel()

	requestContext, cancel := context.WithCancel(context.Background())
	cancel()
	recorder := &fakeAuditedActionRecorder{}

	result, err := finishAuditedAction(requestContext, recorder, store.Action{ID: "action-3"}, auditedOperationOutcome{})
	if err != nil {
		t.Fatalf("finish audited action: %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("action status = %q, want completed", result.Status)
	}
	if recorder.updateContextCanceled.Load() {
		t.Fatal("final audit inherited request cancellation")
	}
	if !recorder.updateHasDeadline.Load() {
		t.Fatal("final audit context did not have a deadline")
	}
}

func TestExecuteAuditedActionRecordsOperationalFailure(t *testing.T) {
	t.Parallel()

	operationErr := errors.New("remote execution failed")
	recorder := &fakeAuditedActionRecorder{}

	result, err := executeAuditedAction(context.Background(), recorder, store.Action{ID: "action-4"}, func() auditedOperationOutcome {
		return auditedOperationOutcome{
			Err:           operationErr,
			ResultSummary: "SSH command failed.",
		}
	})

	if err != nil {
		t.Fatalf("execute audited action: %v", err)
	}
	if !errors.Is(result.OperationErr, operationErr) {
		t.Fatalf("operation error = %v, want %v", result.OperationErr, operationErr)
	}
	if result.FinalAuditErr != nil {
		t.Fatalf("final audit error = %v, want nil", result.FinalAuditErr)
	}
	if result.Action.Status != "failed" || result.Action.ResultSummary != "SSH command failed." {
		t.Fatalf("action = %+v", result.Action)
	}
}

type fakeAuditedActionRecorder struct {
	addErr                error
	updateErr             error
	added                 store.Action
	updated               store.Action
	addCalls              atomic.Int32
	updateCalls           atomic.Int32
	updateContextCanceled atomic.Bool
	updateHasDeadline     atomic.Bool
}

func (r *fakeAuditedActionRecorder) AddAction(_ context.Context, action store.Action) (store.Action, error) {
	r.addCalls.Add(1)
	r.added = action
	if r.addErr != nil {
		return store.Action{}, r.addErr
	}
	return action, nil
}

func (r *fakeAuditedActionRecorder) UpdateAction(ctx context.Context, action store.Action) (store.Action, error) {
	r.updateCalls.Add(1)
	r.updated = action
	r.updateContextCanceled.Store(ctx.Err() != nil)
	_, hasDeadline := ctx.Deadline()
	r.updateHasDeadline.Store(hasDeadline)
	if r.updateErr != nil {
		return store.Action{}, r.updateErr
	}
	return action, nil
}
