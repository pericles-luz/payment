package c6

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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
			// O 503 é repetido (é 5xx); sem isto o teste dorme de verdade.
			p.tokens.sleep = semDormir
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

// TestTokenGrantUsesClientSecretPost pins HOW the credential is presented, which is a
// thing the C6 sandbox measurably cares about: on 21/09/2026, with a valid certificate
// and a valid credential, `Authorization: Basic` answered HTTP 500 — "Condição
// inesperada ao processar requisição." — while the same credential in the form body
// answered 200.
//
// A 500 is the worst possible answer to an authentication mistake: it says the bank
// broke, not that we presented the credential wrong, and it sends whoever is debugging
// to the wrong side. The published contract (docs/compliance/c6-auth-oas.yaml) requires
// client_id, client_secret and grant_type in the body; this test is what keeps a
// "cleanup" from moving them back into a header.
func TestTokenGrantUsesClientSecretPost(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		gotForm  url.Values
		gotAuth  string
		gotCType string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		gotForm = r.PostForm
		gotAuth = r.Header.Get("Authorization")
		gotCType = r.Header.Get("Content-Type")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":600,"scope":"pix.read"}`))
	}))
	defer srv.Close()

	m := newTokenManager(oneTenant("t1", "client-1", "secret-1"), "c6", srv.URL, "", srv.Client(), time.Now)
	if _, err := m.token(context.Background(), "t1"); err != nil {
		t.Fatalf("token: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotForm.Get("grant_type") != "client_credentials" {
		t.Fatalf("grant_type: %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("client_id") != "client-1" || gotForm.Get("client_secret") != "secret-1" {
		t.Fatalf("credential must travel in the body: %v", gotForm)
	}
	// RFC 6749 §2.3.1: a client MUST NOT use more than one authentication method per
	// request, so the header has to be absent, not merely redundant.
	if gotAuth != "" {
		t.Fatalf("no Authorization header may be sent, got %q", gotAuth)
	}
	if gotCType != "application/x-www-form-urlencoded" {
		t.Fatalf("content type: %q", gotCType)
	}
}

// An explicit scope makes the C6 token endpoint answer 400 invalid_request; omitting it
// returns 200 with the credential's full granted scopes. The manager therefore sends
// the parameter ONLY when one was configured — and the default is empty.
func TestTokenOmitsScopeWhenUnset(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		hasScope bool
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		hasScope = r.PostForm.Has("scope")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":600}`))
	}))
	defer srv.Close()

	m := newTokenManager(oneTenant("t1", "c", "s"), "c6", srv.URL, "", srv.Client(), time.Now)
	if _, err := m.token(context.Background(), "t1"); err != nil {
		t.Fatalf("token: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hasScope {
		t.Fatal("an unset scope must not be sent at all")
	}
}

// semDormir substitui a espera entre retentativas para os testes não dormirem.
func semDormir(context.Context, time.Duration) error { return nil }

// TestTokenRetriesServerError trava o comportamento que o sandbox do C6 exigiu: o
// endpoint de token devolve 500 de forma INTERMITENTE.
//
// Medido em 21/09/2026, dezesseis tentativas alternando as duas formas de apresentar a
// credencial: 3/8 de sucesso com ela no corpo, 3/8 com Basic. Não é a forma, é o
// endpoint — e um 500 no token não falha uma chamada, falha todas, porque sem bearer
// não há cobrança nem conciliação.
//
// Repetir é seguro de um jeito que quase nada mais aqui é: o FAQ do C6 (§9) diz que
// gerar um token novo NÃO invalida o atual.
func TestTokenRetriesServerError(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var chamadas int
	ts := newTestServer(t)
	ts.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		chamadas++
		n := chamadas
		mu.Unlock()
		if n <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"title":"Condição inesperada ao processar requisição."}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":600}`))
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"))
	p.tokens.sleep = semDormir

	if _, err := p.tokens.token(context.Background(), "t1"); err != nil {
		t.Fatalf("dois 500 seguidos devem ser atravessados: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if chamadas != 3 {
		t.Fatalf("esperava 3 tentativas, houve %d", chamadas)
	}
}

// A retentativa é LIMITADA: um endpoint realmente caído não vira tráfego infinito.
func TestTokenRetryIsBounded(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var chamadas int
	ts := newTestServer(t)
	ts.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		chamadas++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"title":"erro"}`))
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"))
	p.tokens.sleep = semDormir

	if _, err := p.tokens.token(context.Background(), "t1"); err == nil {
		t.Fatal("500 persistente tem de falhar")
	}
	mu.Lock()
	defer mu.Unlock()
	if want := tokenMaxRetries + 1; chamadas != want {
		t.Fatalf("esperava %d tentativas, houve %d", want, chamadas)
	}
}

// Um 401 é resposta sobre a CREDENCIAL. Repeti-la não a conserta — só transforma um
// erro de configuração em tráfego contra o banco.
func TestTokenDoesNotRetryClientError(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var chamadas int
	ts := newTestServer(t)
	ts.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		chamadas++
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"))
	p.tokens.sleep = semDormir

	if _, err := p.tokens.token(context.Background(), "t1"); !errors.Is(err, shared.ErrUnauthorized) {
		t.Fatalf("esperava ErrUnauthorized, veio %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if chamadas != 1 {
		t.Fatalf("401 não se repete; houve %d tentativas", chamadas)
	}
}
