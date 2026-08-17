package outbound

import (
	"context"
	"math"
	"sync"
	"time"
)

// limiter.go is the per-CONTA outbound rate limiter (SIN-69489 §3 threats D1/D2,
// checklist SSRF/limiter row). A flood of inbound events for one Conta — or that Conta
// pointing us at a slow endpoint — must not let us hammer a destination or starve
// another Conta's deliveries. Each Conta gets its own token bucket, so throttling is
// isolated: Conta A saturating its bucket never delays Conta B (T-LIMITER-peraccount).
//
// It mirrors the C6 outbound token bucket (internal/adapters/bank/c6/ratelimit.go) —
// continuous refill, reservation may go negative so concurrent callers queue fairly —
// without taking a dependency (boring-tech budget), but keyed PER ACCOUNT rather than
// process-wide.

const (
	// defaultAccountRatePerSecond is the steady-state forward rate per Conta. Conservative
	// — a webhook receiver rarely needs more, and a low rate blunts SSRF-as-portscan (D2).
	defaultAccountRatePerSecond = 5.0
	// defaultAccountBurst is the bucket capacity: the largest burst before the steady
	// rate applies.
	defaultAccountBurst = 5.0
)

// waitFunc waits for d or until ctx is done, returning ctx.Err() on cancellation. It is
// injected so tests can assert the requested delay without real sleeps.
type waitFunc func(ctx context.Context, d time.Duration) error

// realWait sleeps for d with a single timer (no goroutine leak) and prompt ctx cancel.
func realWait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// PerAccountLimiter hands out and paces one token bucket per accountID. It satisfies the
// app-layer app.OutboundLimiter port (Wait(ctx, accountID)).
type PerAccountLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*accountBucket
	ratePerSec float64
	capacity   float64
	now        func() time.Time
	wait       waitFunc
}

// NewPerAccountLimiter builds a limiter with the conservative defaults and the real
// clock/sleep.
func NewPerAccountLimiter() *PerAccountLimiter {
	return newPerAccountLimiter(defaultAccountRatePerSecond, defaultAccountBurst, time.Now, realWait)
}

// newPerAccountLimiter is the injectable constructor used by tests to drive timing
// deterministically (fake clock + a recording wait).
func newPerAccountLimiter(ratePerSec, capacity float64, now func() time.Time, wait waitFunc) *PerAccountLimiter {
	return &PerAccountLimiter{
		buckets:    make(map[string]*accountBucket),
		ratePerSec: ratePerSec,
		capacity:   capacity,
		now:        now,
		wait:       wait,
	}
}

// bucketFor returns (creating on first use) the bucket for accountID.
func (l *PerAccountLimiter) bucketFor(accountID string) *accountBucket {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[accountID]
	if !ok {
		b = &accountBucket{tokens: l.capacity, capacity: l.capacity, refillPerSec: l.ratePerSec, now: l.now}
		l.buckets[accountID] = b
	}
	return b
}

// Wait blocks until accountID's bucket admits one forward or ctx is cancelled. A flood
// on one account backs up only that account's callers.
func (l *PerAccountLimiter) Wait(ctx context.Context, accountID string) error {
	if d := l.bucketFor(accountID).reserve(); d > 0 {
		return l.wait(ctx, d)
	}
	return nil
}

// accountBucket is one Conta's token bucket. Tokens refill continuously at refillPerSec
// up to capacity; a reservation may drive the balance negative so concurrent callers are
// queued fairly (each later caller computes a longer wait).
type accountBucket struct {
	mu           sync.Mutex
	tokens       float64
	capacity     float64
	refillPerSec float64
	last         time.Time
	now          func() time.Time
}

// reserve accounts for one forward and returns how long to wait before proceeding (0 when
// a token is immediately available).
func (b *accountBucket) reserve() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if b.last.IsZero() {
		b.last = now
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(b.capacity, b.tokens+elapsed*b.refillPerSec)
	}
	b.last = now

	var wait time.Duration
	if b.tokens < 1 && b.refillPerSec > 0 {
		deficit := 1 - b.tokens
		wait = time.Duration(deficit / b.refillPerSec * float64(time.Second))
	}
	b.tokens--
	return wait
}
