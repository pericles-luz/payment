package c6

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This file adds the outbound-traffic discipline the C6 Termo de Uso de APIs
// requires of a consumer:
//
//   - B11 (clause 3.3): respect a communicated rate limit immediately. When C6
//     answers 429/503 with a Retry-After, we wait exactly that long before the
//     next attempt (and refuse to retry at all when it asks for longer than we
//     are willing to park a request — see maxRetryAfterWait).
//   - A5 (clause 2.5-i/ii/viii): never generate DoS-shaped load. A proactive
//     outbound token bucket caps our request rate to C6, and the retry ceiling is
//     small with exponential backoff + jitter so a degraded PSP is not hammered.
//
// The pre-existing inbound rate limit protects OUR API per tenant/IP; it does not
// govern these outbound calls. This is the missing outbound half (defense in
// depth): both the steady-state limiter and the reactive backoff are honored on
// every C6 request in do().

// Outbound-discipline defaults. All are conservative and overridable per
// environment via Config (RateLimitPerSecond / RateLimitBurst / MaxRetries).
const (
	// defaultRatePerSecond is the steady-state outbound request rate to C6.
	defaultRatePerSecond = 8.0
	// defaultBurst is the token-bucket capacity — the largest burst of requests
	// allowed before the steady rate applies.
	defaultBurst = 8
	// defaultMaxRetries is the number of RETRIES (extra attempts) on a retryable
	// status. Deliberately small so a degraded PSP is never hammered (A5): at most
	// defaultMaxRetries+1 total attempts.
	defaultMaxRetries = 2
	// backoffBase is the first backoff interval when C6 does not send Retry-After.
	backoffBase = 200 * time.Millisecond
	// backoffMaxDelay caps the computed exponential backoff.
	backoffMaxDelay = 8 * time.Second
	// maxRetryAfterWait bounds how long a server-sent Retry-After may park a
	// request. A larger value means we respect the limit by NOT retrying within
	// this call (fail fast with ErrUnavailable) rather than tying up a goroutine —
	// still honoring B11 (we back off at least as long as asked) without a hostile
	// or buggy Retry-After parking us indefinitely.
	maxRetryAfterWait = 30 * time.Second
)

// sleepFunc waits for d or until ctx is done, returning ctx.Err() on
// cancellation. It is injected so tests drive backoff/limiter timing
// deterministically without real sleeps.
type sleepFunc func(ctx context.Context, d time.Duration) error

// realSleep is the production sleep: a single timer, stopped on return, with no
// spawned goroutine (no goroutine leak) and prompt cancellation on ctx.Done.
func realSleep(ctx context.Context, d time.Duration) error {
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

// tokenBucket is a mutex-guarded token bucket that paces outbound C6 requests.
// Tokens refill continuously at refillPerSec up to capacity. A reservation may
// drive the balance negative so concurrent callers are queued fairly (each later
// caller computes a longer wait), mirroring the classic leaky/token-bucket
// reservation used by golang.org/x/time/rate without taking the dependency
// (boring-tech budget).
type tokenBucket struct {
	mu           sync.Mutex
	tokens       float64
	capacity     float64
	refillPerSec float64
	last         time.Time
	now          func() time.Time
}

// reserve accounts for one outbound request and returns how long the caller must
// wait before proceeding (0 when a token is immediately available).
func (tb *tokenBucket) reserve() time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := tb.now()
	if tb.last.IsZero() {
		tb.last = now
	}
	if elapsed := now.Sub(tb.last).Seconds(); elapsed > 0 {
		tb.tokens = math.Min(tb.capacity, tb.tokens+elapsed*tb.refillPerSec)
	}
	tb.last = now

	var wait time.Duration
	if tb.tokens < 1 && tb.refillPerSec > 0 {
		deficit := 1 - tb.tokens
		wait = time.Duration(deficit / tb.refillPerSec * float64(time.Second))
	}
	tb.tokens--
	return wait
}

// wait blocks until the bucket admits one request or ctx is cancelled.
func (tb *tokenBucket) wait(ctx context.Context, sleep sleepFunc) error {
	if d := tb.reserve(); d > 0 {
		return sleep(ctx, d)
	}
	return nil
}

// isRetryableStatus reports whether an upstream status warrants a bounded retry.
// Only 429 (Too Many Requests) and 503 (Service Unavailable) qualify — the two
// statuses C6 uses to signal transient overload/limit. Everything else (incl.
// 5xx other than 503) maps straight to a domain error with no retry, preserving
// the adapter's single-shot posture against retry storms.
func isRetryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
}

// parseRetryAfter parses an HTTP Retry-After header value, which is either
// delta-seconds (a non-negative integer) or an HTTP-date. now anchors the date
// form. Returns (0, false) when absent or unparseable so the caller falls back to
// computed exponential backoff.
func parseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(h); err == nil {
		d := t.Sub(now)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// retryDelay decides how long to wait before the next attempt, and whether to
// retry at all.
//
//   - Retry-After present: honor it exactly (B11 — respect the communicated limit
//     immediately), unless it exceeds maxRetryAfterWait, in which case we do NOT
//     retry within this call (ok=false) so a large/hostile value cannot park the
//     request; the caller returns ErrUnavailable and the work is retried later.
//   - Retry-After absent: exponential backoff base·2^attempt capped at
//     backoffMaxDelay, with "equal jitter" (half fixed, half random) so retries
//     from many callers do not synchronize into a thundering herd (A5).
func (p *Provider) retryDelay(attempt int, retryAfter time.Duration, hasRetryAfter bool) (time.Duration, bool) {
	if hasRetryAfter {
		if retryAfter > maxRetryAfterWait {
			return 0, false
		}
		return retryAfter, true
	}
	d := backoffBase << attempt
	if d <= 0 || d > backoffMaxDelay {
		d = backoffMaxDelay
	}
	half := d / 2
	jitter := time.Duration(p.randFloat() * float64(half))
	return half + jitter, true
}
