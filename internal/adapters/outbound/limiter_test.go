package outbound

import (
	"context"
	"sync"
	"testing"
	"time"
)

// recordingWait captures the delays it is asked to wait (and never really sleeps) so a
// test can assert throttling decisions deterministically.
type recordingWait struct {
	mu    sync.Mutex
	waits []time.Duration
}

func (r *recordingWait) fn(_ context.Context, d time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.waits = append(r.waits, d)
	return nil
}

func (r *recordingWait) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.waits)
}

// T-LIMITER-peraccount: a flood on one Conta throttles only that Conta — a different
// Conta's first forward is admitted immediately. With capacity 1 and a frozen clock (no
// refill), account A's second forward must wait while account B's first must not.
func TestLimiterIsolatesPerAccount(t *testing.T) {
	t.Parallel()
	frozen := time.Date(2026, 8, 17, 15, 0, 0, 0, time.UTC)
	rec := &recordingWait{}
	l := newPerAccountLimiter(1.0, 1.0, func() time.Time { return frozen }, rec.fn)
	ctx := context.Background()

	// A's first forward: token available, no wait.
	if err := l.Wait(ctx, "acct-A"); err != nil {
		t.Fatalf("A#1: %v", err)
	}
	if rec.count() != 0 {
		t.Fatalf("A#1 should not wait, got %d waits", rec.count())
	}
	// A's second forward: bucket empty and clock frozen ⇒ must throttle.
	if err := l.Wait(ctx, "acct-A"); err != nil {
		t.Fatalf("A#2: %v", err)
	}
	if rec.count() != 1 || rec.waits[0] <= 0 {
		t.Fatalf("A#2 should throttle with a positive wait, waits=%v", rec.waits)
	}
	// B's first forward: a SEPARATE bucket ⇒ admitted immediately despite A being saturated.
	if err := l.Wait(ctx, "acct-B"); err != nil {
		t.Fatalf("B#1: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("B#1 must not wait (per-account isolation), total waits=%d", rec.count())
	}
}

// Tokens refill over time: after enough wall-clock the same account is admitted again
// without a wait.
func TestLimiterRefillsOverTime(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 17, 15, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	rec := &recordingWait{}
	l := newPerAccountLimiter(10.0, 1.0, clock, rec.fn)
	ctx := context.Background()

	if err := l.Wait(ctx, "acct-A"); err != nil { // consume the only token
		t.Fatalf("first: %v", err)
	}
	now = now.Add(time.Second) // 10 tokens/s * 1s refills the bucket
	if err := l.Wait(ctx, "acct-A"); err != nil {
		t.Fatalf("second: %v", err)
	}
	if rec.count() != 0 {
		t.Fatalf("after refill the forward should not wait, waits=%v", rec.waits)
	}
}

// realWait returns promptly for a non-positive duration and honors ctx cancellation.
func TestRealWait(t *testing.T) {
	t.Parallel()
	if err := realWait(context.Background(), 0); err != nil {
		t.Fatalf("zero wait: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := realWait(ctx, time.Hour); err == nil {
		t.Fatal("cancelled ctx should return an error")
	}
}

// The production constructor builds a usable limiter (smoke: a first forward is admitted).
func TestNewPerAccountLimiterProduction(t *testing.T) {
	t.Parallel()
	if err := NewPerAccountLimiter().Wait(context.Background(), "acct-A"); err != nil {
		t.Fatalf("production limiter first forward: %v", err)
	}
}
