package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

const (
	maxConcurrentSSHCommands      = 32
	maxConcurrentSSHTerminals     = 16
	maxConcurrentSSHHostKeyProbes = 8
	sshLimitRetryAfter            = "1"
)

var errSSHConcurrencyLimit = errors.New("SSH concurrency limit reached")

type sshConcurrencyLimits struct {
	commands  *sshRequestLimiter
	terminals *sshRequestLimiter
	probes    *sshRequestLimiter
}

type sshRequestLimiter struct {
	slots chan struct{}
}

func newSSHConcurrencyLimits(commandLimit, terminalLimit int) *sshConcurrencyLimits {
	return &sshConcurrencyLimits{
		commands:  newSSHRequestLimiter(commandLimit),
		terminals: newSSHRequestLimiter(terminalLimit),
		probes:    newSSHRequestLimiter(maxConcurrentSSHHostKeyProbes),
	}
}

func newSSHRequestLimiter(limit int) *sshRequestLimiter {
	if limit < 1 {
		panic("SSH concurrency limit must be positive")
	}
	return &sshRequestLimiter{slots: make(chan struct{}, limit)}
}

func (l *sshRequestLimiter) tryAcquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	select {
	case l.slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-l.slots
			return nil, err
		}
		var once sync.Once
		return func() {
			once.Do(func() { <-l.slots })
		}, nil
	default:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errSSHConcurrencyLimit
	}
}

func acquireSSHRequestSlot(w http.ResponseWriter, r *http.Request, limiter *sshRequestLimiter) (func(), bool) {
	release, err := limiter.tryAcquire(r.Context())
	if err == nil {
		return release, true
	}
	if errors.Is(err, errSSHConcurrencyLimit) {
		w.Header().Set("Retry-After", sshLimitRetryAfter)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many concurrent SSH operations"})
	}
	return nil, false
}
