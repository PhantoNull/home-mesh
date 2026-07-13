package networkscan

import (
	"context"
	"sync"
)

type Coordinator struct {
	slot chan struct{}
}

func NewCoordinator() *Coordinator {
	return &Coordinator{slot: make(chan struct{}, 1)}
}

func (c *Coordinator) Acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case c.slot <- struct{}{}:
		return c.releaseFunc(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Coordinator) TryAcquire() (func(), bool) {
	select {
	case c.slot <- struct{}{}:
		return c.releaseFunc(), true
	default:
		return nil, false
	}
}

func (c *Coordinator) releaseFunc() func() {
	var once sync.Once
	return func() {
		once.Do(func() { <-c.slot })
	}
}
