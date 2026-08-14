package http

import (
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// rateLimiter is a small concurrency-safe token-bucket limiter keyed by an
// arbitrary string (tenant id or client IP). It bounds load on expensive
// endpoints (threat H3/W4). The clock is injectable for deterministic tests.
type rateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	capacity float64
	refill   float64 // tokens per second
	now      func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter builds a limiter allowing bursts up to capacity, refilling at
// refillPerSec tokens/second.
func newRateLimiter(capacity, refillPerSec float64, now func() time.Time) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{
		buckets:  make(map[string]*bucket),
		capacity: capacity,
		refill:   refillPerSec,
		now:      now,
	}
}

// allow reports whether a request keyed by key may proceed, consuming a token.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	t := rl.now()
	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{tokens: rl.capacity - 1, last: t}
		return true
	}
	elapsed := t.Sub(b.last).Seconds()
	b.tokens += elapsed * rl.refill
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// middleware limits by the key returned by keyFn (e.g. tenant id, or remote IP).
func (rl *rateLimiter) middleware(keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.allow(keyFn(r)) {
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// middlewareSelfServeCred is the DEDICATED inbound limiter for the self-serve
// credential intake (SIN-69196 Q1). It is deliberately NOT the outbound C6 client
// limiter (SIN-68742) and NOT the shared tenant-plane limiter: credential rotation
// is a rare, high-value write, so it gets its own tight bucket keyed STRICTLY on
// the authenticated tenant (the route sits behind tenant auth, so ctxTenantID is
// always present). retryAfterSecs is emitted on a 429 so a client can back off
// deterministically.
//
// Fail-securely-for-availability: if the tenant key is unexpectedly empty — only
// possible via a wiring bug that placed this middleware before tenant auth — it
// FAILS OPEN (logs a warning and admits the request) rather than throttling. A
// tenant must never be locked out of rotating its own (security-sensitive)
// credential by an internal limiter fault; the route is already authenticated, so
// failing open here does not widen access.
func (rl *rateLimiter) middlewareSelfServeCred(retryAfterSecs int) func(http.Handler) http.Handler {
	retryAfter := strconv.Itoa(retryAfterSecs)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tid := tenantFromContext(r.Context())
			if tid == "" {
				slog.Warn("self-serve credential limiter: empty tenant key; failing open")
				next.ServeHTTP(w, r)
				return
			}
			if !rl.allow("selfserve-cred:" + tid) {
				w.Header().Set("Retry-After", retryAfter)
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// tenantOrIPKey keys by authenticated tenant when present, else remote address.
func tenantOrIPKey(r *http.Request) string {
	if tid := tenantFromContext(r.Context()); tid != "" {
		return "t:" + tid
	}
	return "ip:" + clientIP(r)
}

// adminTokenKey keys the admin-plane limiter by the presented admin token's
// identity, falling back to the client IP when no bearer token is present. The
// token is hashed (never used raw) so the limiter never holds the secret as a map
// key, while each distinct admin identity still gets its own bucket — so one
// admin's burst cannot throttle another sharing the same proxy IP.
func adminTokenKey(r *http.Request) string {
	if tok := bearerToken(r); tok != "" {
		sum := sha256.Sum256([]byte(tok))
		return "admin:" + base64.RawURLEncoding.EncodeToString(sum[:])
	}
	return "ip:" + clientIP(r)
}

func clientIP(r *http.Request) string {
	// Prefer the spoof-resistant client IP resolved by clientIPMiddleware and
	// stored on the request context (never the raw, client-controllable
	// X-Forwarded-For — GO-2026-5775). It is empty only when the configured
	// trusted-proxy depth found no trustworthy hop (fail-closed); fall back to
	// the TCP peer so rate limiting still functions.
	if ip := middleware.GetClientIP(r.Context()); ip != "" {
		return ip
	}
	// RemoteAddr is host:port; strip the port to key on the bare peer IP.
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
