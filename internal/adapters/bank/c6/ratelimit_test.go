package c6

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// sleepRecorder is an injectable sleepFunc that records the durations it was asked
// to wait and returns immediately (so tests never sleep for real). It honors a
// cancelled context so the cancellation paths are still exercised.
type sleepRecorder struct {
	mu   sync.Mutex
	durs []time.Duration
}

func (s *sleepRecorder) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.durs = append(s.durs, d)
	s.mu.Unlock()
	return nil
}

func (s *sleepRecorder) waits() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]time.Duration, len(s.durs))
	copy(out, s.durs)
	return out
}

// deterministic wires a provider for retry/backoff tests: a recording sleep (no
// real waits) and a fixed jitter source so backoff delays are exact. It also
// pushes the token-bucket burst high enough that the outbound limiter never fires
// during these small tests, isolating the backoff behaviour under assertion.
func deterministic(p *Provider, rec *sleepRecorder, jitter float64) {
	p.sleep = rec.sleep
	p.randFloat = func() float64 { return jitter }
	p.limiter = &tokenBucket{tokens: 1000, capacity: 1000, refillPerSec: 1000, now: p.now}
}

// statusThenOK returns a handler that answers `status` (optionally with a
// Retry-After header) for the first `n` calls, then a happy 200. hits counts
// calls; idem records the Idempotency-Key seen on every call.
func statusThenOK(n, status int, retryAfter string, hits *int, idem *[]string) http.HandlerFunc {
	var mu sync.Mutex
	return func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*hits++
		call := *hits
		if idem != nil {
			*idem = append(*idem, r.Header.Get("Idempotency-Key"))
		}
		mu.Unlock()
		if call <= n {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"tx_123","status":"pending"}`))
	}
}

func newCharge() ports.ChargeRequest {
	return ports.ChargeRequest{TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL"}
}

// TestRetryAfterHonored covers the 429/503-with-Retry-After branch (Termo B11):
// the client waits exactly the communicated interval before retrying, then
// succeeds. Both delta-seconds and the retryable statuses are exercised.
func TestRetryAfterHonored(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header string
		want   time.Duration
	}{
		{"429 retry-after 2s", http.StatusTooManyRequests, "2", 2 * time.Second},
		{"503 retry-after 5s", http.StatusServiceUnavailable, "5", 5 * time.Second},
		{"429 retry-after zero", http.StatusTooManyRequests, "0", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t)
			var hits int
			ts.createHandler = statusThenOK(1, tc.status, tc.header, &hits, nil)
			p := ts.provider(t, oneTenant("t1", "c1", "s1"))
			rec := &sleepRecorder{}
			deterministic(p, rec, 0)

			if _, err := p.CreateCharge(context.Background(), "t1", newCharge()); err != nil {
				t.Fatalf("expected success after honored Retry-After, got %v", err)
			}
			if hits != 2 {
				t.Fatalf("want 2 upstream hits (fail+retry), got %d", hits)
			}
			got := rec.waits()
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("want single wait of %v, got %v", tc.want, got)
			}
		})
	}
}

// TestBackoffWithoutRetryAfter covers the exponential-backoff branch (no
// Retry-After): with jitter pinned to 0 the delay is the fixed "equal jitter"
// floor base·2^attempt / 2, doubling each attempt. Proves backoff grows and is
// bounded (small ceiling ⇒ no retry storm, Termo A5).
func TestBackoffWithoutRetryAfter(t *testing.T) {
	ts := newTestServer(t)
	var hits int
	// Two 429s then success ⇒ two backoff waits (default maxRetries = 2).
	ts.createHandler = statusThenOK(2, http.StatusTooManyRequests, "", &hits, nil)
	p := ts.provider(t, oneTenant("t1", "c1", "s1"))
	rec := &sleepRecorder{}
	deterministic(p, rec, 0)

	if _, err := p.CreateCharge(context.Background(), "t1", newCharge()); err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}
	got := rec.waits()
	want := []time.Duration{backoffBase / 2, backoffBase} // 100ms, 200ms
	if len(got) != len(want) {
		t.Fatalf("want %d backoff waits, got %v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff wait %d: want %v got %v (all: %v)", i, want[i], got[i], got)
		}
	}
	if hits != 3 {
		t.Fatalf("want 3 hits (2 fail + 1 ok), got %d", hits)
	}
}

// TestBackoffJitterBounds verifies the jitter stays within [floor, ceil] for the
// full random range, so a hostile/degenerate rand cannot exceed the cap or drop
// below the equal-jitter floor.
func TestBackoffJitterBounds(t *testing.T) {
	p := &Provider{randFloat: func() float64 { return 1 }} // max jitter
	d, ok := p.retryDelay(0, 0, false)
	if !ok || d != backoffBase { // floor(100ms) + jitter(100ms) = 200ms
		t.Fatalf("max jitter attempt 0: want %v, got %v (ok=%v)", backoffBase, d, ok)
	}
	p.randFloat = func() float64 { return 0 } // min jitter ⇒ floor
	d, _ = p.retryDelay(0, 0, false)
	if d != backoffBase/2 {
		t.Fatalf("min jitter attempt 0: want %v, got %v", backoffBase/2, d)
	}
	// High attempt is capped at backoffMaxDelay (floor = cap/2).
	p.randFloat = func() float64 { return 0 }
	if d, _ := p.retryDelay(20, 0, false); d != backoffMaxDelay/2 {
		t.Fatalf("attempt 20 should cap: want floor %v, got %v", backoffMaxDelay/2, d)
	}
}

// TestRetryCeiling proves the retry count is bounded: a permanently failing
// retryable status is attempted maxRetries+1 times and then surfaces
// ErrUnavailable — no infinite retry storm (Termo A5).
func TestRetryCeiling(t *testing.T) {
	ts := newTestServer(t)
	var hits int
	ts.createHandler = statusThenOK(1_000_000, http.StatusServiceUnavailable, "", &hits, nil)
	p := ts.provider(t, oneTenant("t1", "c1", "s1"))
	rec := &sleepRecorder{}
	deterministic(p, rec, 0)

	_, err := p.CreateCharge(context.Background(), "t1", newCharge())
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable after ceiling, got %v", err)
	}
	if hits != defaultMaxRetries+1 {
		t.Fatalf("want %d hits (1 + %d retries), got %d", defaultMaxRetries+1, defaultMaxRetries, hits)
	}
	if n := len(rec.waits()); n != defaultMaxRetries {
		t.Fatalf("want %d backoff waits, got %d", defaultMaxRetries, n)
	}
}

// TestRetryAfterTooLargeFailsFast: a Retry-After longer than we will park a
// request means we do NOT retry within this call — one attempt, immediate
// ErrUnavailable, no sleep. Honors B11 (we back off at least as long as asked, by
// not retrying) without a hostile value tying up a goroutine.
func TestRetryAfterTooLargeFailsFast(t *testing.T) {
	ts := newTestServer(t)
	var hits int
	ts.createHandler = statusThenOK(1_000_000, http.StatusTooManyRequests, "99999", &hits, nil)
	p := ts.provider(t, oneTenant("t1", "c1", "s1"))
	rec := &sleepRecorder{}
	deterministic(p, rec, 0)

	_, err := p.CreateCharge(context.Background(), "t1", newCharge())
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if hits != 1 {
		t.Fatalf("want a single attempt (no retry), got %d", hits)
	}
	if n := len(rec.waits()); n != 0 {
		t.Fatalf("want no sleeps, got %d", n)
	}
}

// TestNoRetryOnNonRetryableStatus: a 400 is a client error, never retried.
func TestNoRetryOnNonRetryableStatus(t *testing.T) {
	ts := newTestServer(t)
	var hits int
	ts.createHandler = statusThenOK(1_000_000, http.StatusBadRequest, "", &hits, nil)
	p := ts.provider(t, oneTenant("t1", "c1", "s1"))
	rec := &sleepRecorder{}
	deterministic(p, rec, 0)

	_, err := p.CreateCharge(context.Background(), "t1", newCharge())
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	if hits != 1 {
		t.Fatalf("want a single attempt for 400, got %d", hits)
	}
	if n := len(rec.waits()); n != 0 {
		t.Fatalf("400 must not back off, got %d sleeps", n)
	}
}

// TestIdempotencyKeyStableAcrossRetries: every retried write carries the SAME
// Idempotency-Key, so a safe retry collapses to one effect at C6 and can never
// double-charge (the retry+idempotency invariant).
func TestIdempotencyKeyStableAcrossRetries(t *testing.T) {
	ts := newTestServer(t)
	var hits int
	var idem []string
	ts.createHandler = statusThenOK(2, http.StatusTooManyRequests, "", &hits, &idem)
	p := ts.provider(t, oneTenant("t1", "c1", "s1"))
	rec := &sleepRecorder{}
	deterministic(p, rec, 0)

	req := newCharge()
	req.IdempotencyKey = "idem-abc"
	if _, err := p.CreateCharge(context.Background(), "t1", req); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(idem) != 3 {
		t.Fatalf("want 3 attempts recorded, got %d", len(idem))
	}
	for i, k := range idem {
		if k != "idem-abc" {
			t.Fatalf("attempt %d idempotency key drifted: %q", i, k)
		}
	}
}

// TestContextCancelDuringBackoff: a context cancelled while backing off aborts the
// retry loop and surfaces ErrUnavailable rather than hanging.
func TestContextCancelDuringBackoff(t *testing.T) {
	ts := newTestServer(t)
	var hits int
	ts.createHandler = statusThenOK(1_000_000, http.StatusServiceUnavailable, "", &hits, nil)
	p := ts.provider(t, oneTenant("t1", "c1", "s1"))
	ctx, cancel := context.WithCancel(context.Background())
	// A sleep that cancels the context, so the first backoff wait returns ctx.Err().
	p.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
	p.randFloat = func() float64 { return 0 }
	p.limiter = &tokenBucket{tokens: 1000, capacity: 1000, refillPerSec: 1000, now: p.now}

	_, err := p.CreateCharge(ctx, "t1", newCharge())
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on cancel, got %v", err)
	}
	if hits != 1 {
		t.Fatalf("want a single attempt before cancel, got %d", hits)
	}
}

// TestOutboundRateLimitEnforced proves the proactive token bucket actually paces
// outbound requests end-to-end: with a burst of 1 and a frozen clock (no refill),
// the second call must wait for the bucket before hitting C6 (Termo A5).
func TestOutboundRateLimitEnforced(t *testing.T) {
	ts := newTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c1", "s1"))
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p.now = clk.now
	p.limiter = &tokenBucket{tokens: 1, capacity: 1, refillPerSec: 1, now: clk.now}
	rec := &sleepRecorder{}
	p.sleep = rec.sleep

	// First read: one burst token available ⇒ no wait.
	if _, err := p.GetCharge(context.Background(), "t1", "tx_123"); err != nil {
		t.Fatalf("first GetCharge: %v", err)
	}
	if n := len(rec.waits()); n != 0 {
		t.Fatalf("first call should not wait, got %v", rec.waits())
	}
	// Second read with the clock frozen ⇒ no refill ⇒ must wait ~1/rate = 1s.
	if _, err := p.GetCharge(context.Background(), "t1", "tx_123"); err != nil {
		t.Fatalf("second GetCharge: %v", err)
	}
	got := rec.waits()
	if len(got) != 1 || got[0] != time.Second {
		t.Fatalf("second call must wait 1s for the bucket, got %v", got)
	}
	if ts.getHits != 2 {
		t.Fatalf("both reads should reach C6, got %d", ts.getHits)
	}
}

// TestTokenBucketReserve unit-tests the bucket's reservation accounting against a
// manually-advanced clock, including the negative-balance queueing of bursts.
func TestTokenBucketReserve(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	tb := &tokenBucket{tokens: 2, capacity: 2, refillPerSec: 1, now: clk.now}

	if d := tb.reserve(); d != 0 { // token 1 of burst
		t.Fatalf("burst 1: want 0, got %v", d)
	}
	if d := tb.reserve(); d != 0 { // token 2 of burst
		t.Fatalf("burst 2: want 0, got %v", d)
	}
	if d := tb.reserve(); d != time.Second { // empty ⇒ 1s for one token
		t.Fatalf("empty bucket: want 1s, got %v", d)
	}
	if d := tb.reserve(); d != 2*time.Second { // balance -1 ⇒ 2s
		t.Fatalf("queued reservation: want 2s, got %v", d)
	}
	clk.advance(3 * time.Second) // refills back to +1 (capped)
	if d := tb.reserve(); d != 0 {
		t.Fatalf("after refill: want 0, got %v", d)
	}
}

// TestParseRetryAfter covers the delta-seconds, HTTP-date, and rejected forms.
func TestParseRetryAfter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cases := []struct {
		name    string
		header  string
		now     time.Time
		want    time.Duration
		present bool
	}{
		{"empty", "", now, 0, false},
		{"seconds", "7", now, 7 * time.Second, true},
		{"zero", "0", now, 0, true},
		{"negative rejected", "-3", now, 0, false},
		{"garbage rejected", "soon", now, 0, false},
		{"http-date future", now.Add(10 * time.Second).Format(http.TimeFormat), now, 10 * time.Second, true},
		{"http-date past clamps to zero", now.Add(-10 * time.Second).Format(http.TimeFormat), now, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, present := parseRetryAfter(tc.header, tc.now)
			if present != tc.present || got != tc.want {
				t.Fatalf("parseRetryAfter(%q): want (%v,%v), got (%v,%v)", tc.header, tc.want, tc.present, got, present)
			}
		})
	}
}

// TestRealSleepCancelAndNoLeak: realSleep returns promptly on a cancelled context
// (with ctx.Err), returns nil for a completed short wait, and spawns no goroutine
// that outlives it (no goroutine leak).
func TestRealSleepCancelAndNoLeak(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := realSleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancelled sleep should return promptly, took %v", elapsed)
	}
	// A short, completing sleep returns nil.
	if err := realSleep(context.Background(), 2*time.Millisecond); err != nil {
		t.Fatalf("short sleep: want nil, got %v", err)
	}
	// Non-positive duration returns ctx.Err() (nil here) without blocking.
	if err := realSleep(context.Background(), 0); err != nil {
		t.Fatalf("zero sleep: want nil, got %v", err)
	}

	runtime.GC()
	before := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		c, cn := context.WithCancel(context.Background())
		cn()
		_ = realSleep(c, time.Hour)
	}
	time.Sleep(20 * time.Millisecond)
	runtime.GC()
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

// TestMaxRetriesConfig verifies New's normalisation: zero ⇒ default, negative ⇒
// single-shot, positive ⇒ honored; and that rate/burst defaults are applied.
func TestMaxRetriesConfig(t *testing.T) {
	creds := oneTenant("t1", "c1", "s1")
	base := Config{BaseURL: "https://api.example", TokenURL: "https://t/oauth"}

	base.MaxRetries = 0
	if p, _ := New(base, creds); p.maxRetries != defaultMaxRetries {
		t.Fatalf("zero MaxRetries: want default %d, got %d", defaultMaxRetries, p.maxRetries)
	}
	base.MaxRetries = -1
	if p, _ := New(base, creds); p.maxRetries != 0 {
		t.Fatalf("negative MaxRetries: want single-shot 0, got %d", p.maxRetries)
	}
	base.MaxRetries = 5
	if p, _ := New(base, creds); p.maxRetries != 5 {
		t.Fatalf("explicit MaxRetries: want 5, got %d", p.maxRetries)
	}
	base.MaxRetries = 0
	p, _ := New(base, creds)
	if p.limiter == nil || p.limiter.capacity != float64(defaultBurst) || p.limiter.refillPerSec != defaultRatePerSecond {
		t.Fatalf("limiter defaults not applied: %+v", p.limiter)
	}
}

// TestNegativeMaxRetriesIsSingleShot: with retries disabled a 503 fails on the
// first attempt (proves the single-shot escape hatch).
func TestNegativeMaxRetriesIsSingleShot(t *testing.T) {
	ts := newTestServer(t)
	var hits int
	ts.createHandler = statusThenOK(1_000_000, http.StatusServiceUnavailable, "", &hits, nil)
	p, err := New(Config{BaseURL: ts.URL, TokenURL: ts.URL + "/oauth/token", HTTPClient: ts.Client(), MaxRetries: -1}, oneTenant("t1", "c1", "s1"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := &sleepRecorder{}
	p.sleep = rec.sleep

	if _, err := p.CreateCharge(context.Background(), "t1", newCharge()); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if hits != 1 {
		t.Fatalf("single-shot: want 1 hit, got %d", hits)
	}
	if n := len(rec.waits()); n != 0 {
		t.Fatalf("single-shot: want no backoff, got %d", n)
	}
}
