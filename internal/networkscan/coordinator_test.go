package networkscan

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCoordinatorWaitsWithContextAndTryAcquireDoesNotBlock(t *testing.T) {
	coordinator := NewCoordinator()
	canceled, cancelImmediately := context.WithCancel(context.Background())
	cancelImmediately()
	if _, err := coordinator.Acquire(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled Acquire error = %v", err)
	}
	release, err := coordinator.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := coordinator.TryAcquire(); ok {
		t.Fatal("TryAcquire succeeded while the coordinator was occupied")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := coordinator.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire error = %v", err)
	}

	release()
	release()
	secondRelease, ok := coordinator.TryAcquire()
	if !ok {
		t.Fatal("TryAcquire failed after release")
	}
	secondRelease()
}
