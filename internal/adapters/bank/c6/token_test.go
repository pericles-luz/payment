package c6

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fakeClock is a manually-advanced clock for deterministic token-expiry tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func tokenProvider(t *testing.T, ts *testServer, creds ports.CredentialStore, now func() time.Time) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL:    ts.URL,
		TokenURL:   ts.URL + "/oauth/token",
		HTTPClient: ts.Client(),
		Now:        now,
	}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestTokenCacheHit(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c1", "s1"))

	for i := 0; i < 3; i++ {
		if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
			t.Fatalf("token call %d: %v", i, err)
		}
	}
	if ts.tokenHits != 1 {
		t.Fatalf("expected a single token fetch (cache hits after), got %d", ts.tokenHits)
	}
}

func TestTokenProactiveRefreshOnExpiry(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	// Token lives 3600s; refresh skew is 30s.
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p := tokenProvider(t, ts, oneTenant("t1", "c1", "s1"), clk.now)

	if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	// Still well within validity → cached.
	clk.advance(3000 * time.Second)
	if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	if ts.tokenHits != 1 {
		t.Fatalf("token should still be cached, hits=%d", ts.tokenHits)
	}
	// Cross into the refresh-skew window (3600-30=3570s) → proactive refresh.
	clk.advance(580 * time.Second) // total 3580s > 3570s
	if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	if ts.tokenHits != 2 {
		t.Fatalf("token should have been refreshed proactively, hits=%d", ts.tokenHits)
	}
}

func TestTokenPerTenantIsolation(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	creds := &fakeCreds{creds: map[string]ports.BankCredential{
		"t1": {TenantID: "t1", ClientID: "client-1", Secret: "s1"},
		"t2": {TenantID: "t2", ClientID: "client-2", Secret: "s2"},
	}}
	p := ts.provider(t, creds)

	tok1, err := p.tokens.token(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := p.tokens.token(context.Background(), "t2")
	if err != nil {
		t.Fatal(err)
	}
	if tok1 == tok2 {
		t.Fatalf("tenants must not share a token: %q == %q", tok1, tok2)
	}
	if tok1 != "tok-client-1" || tok2 != "tok-client-2" {
		t.Fatalf("tokens not derived from each tenant's own credential: %q %q", tok1, tok2)
	}
	// Two distinct tenants → two distinct fetches.
	if ts.tokenHits != 2 {
		t.Fatalf("expected one fetch per tenant, hits=%d", ts.tokenHits)
	}
	// Re-requesting t1 stays cached and never returns t2's token.
	again, err := p.tokens.token(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if again != tok1 || ts.tokenHits != 2 {
		t.Fatalf("t1 cache broken: tok=%q hits=%d", again, ts.tokenHits)
	}
}

func TestTokenFetchErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"unauthorized", http.StatusUnauthorized, shared.ErrUnauthorized},
		{"forbidden", http.StatusForbidden, shared.ErrUnauthorized},
		{"unavailable", http.StatusServiceUnavailable, shared.ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := newTestServer(t)
			ts.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":"e"}`))
			}
			p := ts.provider(t, oneTenant("t1", "c", "s"))
			if _, err := p.tokens.token(context.Background(), "t1"); !errors.Is(err, tc.want) {
				t.Fatalf("status %d: want %v, got %v", tc.status, tc.want, err)
			}
		})
	}
}

func TestTokenMissingAccessToken(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":60}`)) // no access_token
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.tokens.token(context.Background(), "t1"); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("2xx without access_token should be ErrUnavailable, got %v", err)
	}
}

func TestTokenFallbackTTL(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-x","token_type":"Bearer"}`)) // no expires_in
	}
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p := tokenProvider(t, ts, oneTenant("t1", "c", "s"), clk.now)

	if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	// Within the fallback TTL (60s) minus skew (30s) → still cached.
	clk.advance(20 * time.Second)
	if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	if ts.tokenHits != 1 {
		t.Fatalf("token within fallback TTL should be cached, hits=%d", ts.tokenHits)
	}
	// Past fallback TTL - skew → refetch.
	clk.advance(20 * time.Second) // total 40s > (60-30)=30s
	if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	if ts.tokenHits != 2 {
		t.Fatalf("token past fallback TTL should refetch, hits=%d", ts.tokenHits)
	}
}

func TestTokenCredentialError(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	p := ts.provider(t, &fakeCreds{err: shared.ErrNotFound})
	if _, err := p.tokens.token(context.Background(), "t1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("credential error must propagate, got %v", err)
	}
	if ts.tokenHits != 0 {
		t.Fatalf("token endpoint must not be hit when the credential is missing, hits=%d", ts.tokenHits)
	}
}

// TestTokenInvalidateForcesRefetch is the token-revocation-lag fix (ADR-0003):
// after a credential rotation the cached bearer would otherwise survive until
// expiry. invalidate() drops it so the next call mints a fresh token under the
// new credential.
func TestTokenInvalidateForcesRefetch(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	creds := oneTenant("t1", "c1", "s1")
	p := ts.provider(t, creds)

	first, err := p.tokens.token(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if first != "tok-c1" || ts.tokenHits != 1 {
		t.Fatalf("first fetch: tok=%q hits=%d", first, ts.tokenHits)
	}

	// Rotate the credential. Without eviction the cache still serves the old token
	// (the lag this fix closes).
	creds.creds["t1"] = ports.BankCredential{TenantID: "t1", ClientID: "c2", Secret: "s2"}
	stale, err := p.tokens.token(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if stale != "tok-c1" || ts.tokenHits != 1 {
		t.Fatalf("pre-evict should still be cached under old cred: tok=%q hits=%d", stale, ts.tokenHits)
	}

	// Evict, then the next call mints a token under the rotated credential.
	p.tokens.invalidate("t1")
	fresh, err := p.tokens.token(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if fresh != "tok-c2" || ts.tokenHits != 2 {
		t.Fatalf("post-evict should refetch under new cred: tok=%q hits=%d", fresh, ts.tokenHits)
	}
}

// TestTokenInvalidateIsPerTenant asserts evicting one tenant never disturbs
// another tenant's cached token.
func TestTokenInvalidateIsPerTenant(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	creds := &fakeCreds{creds: map[string]ports.BankCredential{
		"t1": {TenantID: "t1", ClientID: "c1", Secret: "s1"},
		"t2": {TenantID: "t2", ClientID: "c2", Secret: "s2"},
	}}
	p := ts.provider(t, creds)

	if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.tokens.token(context.Background(), "t2"); err != nil {
		t.Fatal(err)
	}
	if ts.tokenHits != 2 {
		t.Fatalf("expected one fetch per tenant, hits=%d", ts.tokenHits)
	}

	p.tokens.invalidate("t1")
	// t2 stays cached (no extra fetch); t1 refetches.
	if _, err := p.tokens.token(context.Background(), "t2"); err != nil {
		t.Fatal(err)
	}
	if ts.tokenHits != 2 {
		t.Fatalf("evicting t1 must not touch t2's cache, hits=%d", ts.tokenHits)
	}
	if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	if ts.tokenHits != 3 {
		t.Fatalf("t1 should have refetched after eviction, hits=%d", ts.tokenHits)
	}
}

// TestTokenInvalidateUnknownTenant is a no-op (and must not panic) when the
// tenant has no cache slot — the admin plane may evict before any token was ever
// minted for that tenant.
func TestTokenInvalidateUnknownTenant(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c1", "s1"))
	p.tokens.invalidate("never-seen")
	if ts.tokenHits != 0 {
		t.Fatalf("invalidate must not trigger a fetch, hits=%d", ts.tokenHits)
	}
	// The provider-level entrypoint is the wiring the admin plane uses.
	p.InvalidateToken("never-seen")
}

// TestTokenConcurrentSameTenant exercises the per-tenant lock: many concurrent
// callers for one tenant must all succeed (race detector guards correctness).
func TestTokenConcurrentSameTenant(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c1", "s1"))

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
				t.Errorf("concurrent token: %v", err)
			}
		}()
	}
	wg.Wait()
}
