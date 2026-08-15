package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// probe200 is a trivial handler that records whether it ran and answers 200.
func probe200(ran *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusOK)
	})
}

// TestAccountKeyRotateLimiterThrottles: once the per-account bucket is empty the
// limiter answers 429 and advertises Retry-After, and the wrapped handler does not
// run.
func TestAccountKeyRotateLimiterThrottles(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(1, 0, nil) // capacity 1, no refill
	var ran bool
	h := rl.middlewareAccountKeyRotate(60)(probe200(&ran))

	req := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/account-key", nil)
		r = r.WithContext(context.WithValue(r.Context(), ctxAccountID, "acct-A"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	if rec := req(); rec.Code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", rec.Code)
	}
	ran = false
	rec := req()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: want 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("want Retry-After: 60, got %q", rec.Header().Get("Retry-After"))
	}
	if ran {
		t.Fatalf("handler ran despite the 429")
	}
}

// TestAccountKeyRotateLimiterFailsOpen: with no account on the context (only
// reachable via a wiring bug placing the limiter before auth), the limiter admits
// the request rather than locking the caller out of rotating its credential.
func TestAccountKeyRotateLimiterFailsOpen(t *testing.T) {
	t.Parallel()
	rl := newRateLimiter(0, 0, nil) // a real key would be throttled immediately
	var ran bool
	h := rl.middlewareAccountKeyRotate(60)(probe200(&ran))

	r := httptest.NewRequest(http.MethodPost, "/v1/account-key", nil) // no ctxAccountID
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK || !ran {
		t.Fatalf("want fail-open 200 with handler run, got code=%d ran=%v", rec.Code, ran)
	}
}
