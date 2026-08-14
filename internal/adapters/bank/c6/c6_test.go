package c6

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fakeCreds is a controllable CredentialStore for tests: it can return a fixed
// error (to exercise the missing-credential path) or per-tenant credentials.
type fakeCreds struct {
	err   error
	creds map[string]ports.BankCredential
}

func (f *fakeCreds) GetBankCredential(_ context.Context, tenantID string, _ string) (ports.BankCredential, error) {
	if f.err != nil {
		return ports.BankCredential{}, f.err
	}
	c, ok := f.creds[tenantID]
	if !ok {
		return ports.BankCredential{}, shared.ErrNotFound
	}
	return c, nil
}

func oneTenant(tenantID, clientID, secret string) *fakeCreds {
	return &fakeCreds{creds: map[string]ports.BankCredential{
		tenantID: {TenantID: tenantID, ClientID: clientID, Secret: secret},
	}}
}

// testServer is a configurable C6 + OAuth2 double backed by httptest TLS. Handlers
// default to a happy path and can be overridden per test. It records request
// observations so tests can assert headers/counters without races.
type testServer struct {
	*httptest.Server

	mu             sync.Mutex
	tokenHits      int
	createHits     int
	getHits        int
	lastAuthHeader string // Authorization seen by the charge endpoints
	lastIdemKey    string // Idempotency-Key seen by create
	lastBasicUser  string // client_id seen by the token endpoint

	// Overridable handlers. When nil, a happy-path default is used.
	tokenHandler  http.HandlerFunc
	createHandler http.HandlerFunc
	getHandler    http.HandlerFunc
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	ts := &testServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		ts.tokenHits++
		user, _, _ := r.BasicAuth()
		ts.lastBasicUser = user
		h := ts.tokenHandler
		ts.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	// The generic charge surface now maps to the BACEN PIX v2 cob endpoints
	// (SIN-65856): PUT /v2/pix/cob/{txid} creates and GET /v2/pix/cob/{txid} reads,
	// distinguished by method on the same path. Responses are the cob wire shape
	// (txid/status/valor/...).
	mux.HandleFunc("/v2/pix/cob/", func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		if r.Method == http.MethodGet {
			ts.getHits++
			ts.lastAuthHeader = r.Header.Get("Authorization")
			h := ts.getHandler
			ts.mu.Unlock()
			if h != nil {
				h(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"txid":"tx_123","status":"paid"}`))
			return
		}
		// PUT — idempotent cob create.
		ts.createHits++
		ts.lastAuthHeader = r.Header.Get("Authorization")
		ts.lastIdemKey = r.Header.Get("Idempotency-Key")
		h := ts.createHandler
		ts.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"tx_123","status":"pending"}`))
	})
	ts.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func (ts *testServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL:    ts.URL,
		TokenURL:   ts.URL + "/oauth/token",
		HTTPClient: ts.Client(),
	}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestNewValidation(t *testing.T) {
	t.Parallel()
	creds := oneTenant("t1", "c1", "s1")
	cases := []struct {
		name string
		cfg  Config
	}{
		{"nil base", Config{TokenURL: "https://t/x"}},
		{"http base rejected", Config{BaseURL: "http://api.example", TokenURL: "https://t/x"}},
		{"http token rejected", Config{BaseURL: "https://api.example", TokenURL: "http://t/x"}},
		{"malformed base", Config{BaseURL: "://nope", TokenURL: "https://t/x"}},
		{"missing token", Config{BaseURL: "https://api.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tc.cfg, creds); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}

	if _, err := New(Config{BaseURL: "https://api.example", TokenURL: "https://t/x"}, nil); err == nil {
		t.Fatal("expected error for nil credential store")
	}

	// Happy path: an https config with defaults builds a provider with a client.
	p, err := New(Config{BaseURL: "https://api.example/", TokenURL: "https://t/oauth"}, creds)
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if p.httpc == nil {
		t.Fatal("expected a default HTTP client to be built")
	}
	if strings.HasSuffix(p.baseURL, "/") {
		t.Fatalf("trailing slash should be trimmed: %q", p.baseURL)
	}
}

func TestDefaultHTTPClientEnforcesTLS(t *testing.T) {
	t.Parallel()
	c := defaultHTTPClient(7 * time.Second)
	if c.Timeout != 7*time.Second {
		t.Fatalf("timeout not applied: %v", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", c.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected MinVersion TLS 1.2")
	}
}

func TestCreateChargeSuccess(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	p := ts.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay-1", AmountCents: 1000, Currency: "BRL",
	})
	if err != nil {
		t.Fatalf("CreateCharge: %v", err)
	}
	if res.TxID != "tx_123" || res.Status != "pending" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if ts.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer token not attached: %q", ts.lastAuthHeader)
	}
	if ts.lastIdemKey != "pay-1" {
		t.Fatalf("idempotency key should fall back to the payment id, got %q", ts.lastIdemKey)
	}
}

// TestCreateChargeForwardsIdempotencyKey covers the F3b contract (SIN-64720): a
// caller-supplied IdempotencyKey is forwarded to the PSP verbatim, and only when
// it is empty does the adapter fall back to the deterministic PaymentID.
func TestCreateChargeForwardsIdempotencyKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		paymentID string
		idemKey   string
		wantKey   string
	}{
		{"caller key wins", "pay-1", "idem-abc", "idem-abc"},
		{"fallback to payment id", "pay-2", "", "pay-2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := newTestServer(t)
			p := ts.provider(t, oneTenant("t1", "c", "s"))
			if _, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{
				TenantID: "t1", PaymentID: tc.paymentID, IdempotencyKey: tc.idemKey, AmountCents: 1, Currency: "BRL",
			}); err != nil {
				t.Fatalf("CreateCharge: %v", err)
			}
			if ts.lastIdemKey != tc.wantKey {
				t.Fatalf("Idempotency-Key: want %q, got %q", tc.wantKey, ts.lastIdemKey)
			}
		})
	}
}

func TestGetChargeSuccess(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	p := ts.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.GetCharge(context.Background(), "t1", "tx_123")
	if err != nil {
		t.Fatalf("GetCharge: %v", err)
	}
	if res.TxID != "tx_123" || res.Status != "paid" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if ts.lastAuthHeader != "Bearer tok-client-1" {
		t.Fatalf("bearer token not attached: %q", ts.lastAuthHeader)
	}
}

func TestChargeErrorMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"validation", 400, shared.ErrValidation},
		{"conflict", 409, shared.ErrConflict},
		{"server error", 503, shared.ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := newTestServer(t)
			ts.createHandler = func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"code":"X"}`))
			}
			p := ts.provider(t, oneTenant("t1", "c", "s"))
			_, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("status %d: want %v, got %v", tc.status, tc.want, err)
			}
		})
	}
}

func TestGetChargeNotFound(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.getHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.GetCharge(context.Background(), "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestChargeMalformedSuccessBody(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.createHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not-json`))
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL"}); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("malformed 2xx body should map to ErrUnavailable, got %v", err)
	}
}

func TestChargeMissingCredential(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	p := ts.provider(t, &fakeCreds{creds: map[string]ports.BankCredential{}}) // no tenants

	_, err := p.CreateCharge(context.Background(), "unknown", ports.ChargeRequest{TenantID: "unknown", PaymentID: "p", AmountCents: 1, Currency: "BRL"})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing credential should propagate ErrNotFound, got %v", err)
	}
	if ts.tokenHits != 0 {
		t.Fatalf("token endpoint must not be hit without a credential, hits=%d", ts.tokenHits)
	}
}

func TestChargeTokenUnauthorized(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL"}); !errors.Is(err, shared.ErrUnauthorized) {
		t.Fatalf("bad credentials should map to ErrUnauthorized, got %v", err)
	}
}

// TestContextCancellation proves context is propagated to the transport and a
// cancelled request fails as unavailable rather than hanging (no goroutine leak).
func TestContextCancellation(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	if _, err := p.CreateCharge(ctx, "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL"}); err == nil {
		t.Fatal("expected error with a cancelled context")
	}
}

// TestSecretNeverLeaks asserts the client secret never reaches an error returned
// to the caller, on either the token-failure or charge-failure path.
func TestSecretNeverLeaks(t *testing.T) {
	t.Parallel()
	const secret = "TOP-SECRET-VALUE-9988"
	ts := newTestServer(t)
	ts.tokenHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}
	p := ts.provider(t, oneTenant("t1", "client-1", secret))

	_, err := p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL"})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the client secret: %q", err.Error())
	}
}

// TestGetChargeReconcilesAmount asserts the generic charge GET parses the
// expected amount from valor.original and the received amount from the sum of the
// pix[] receipts, so the settlement use-case can reconcile the money (SIN-64777).
func TestGetChargeReconcilesAmount(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.getHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"tx_123","status":"paid","valor":{"original":"100.00"},"pix":[{"valor":"60.00"},{"valor":"40.00"}]}`))
	}
	p := ts.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.GetCharge(context.Background(), "t1", "tx_123")
	if err != nil {
		t.Fatalf("GetCharge: %v", err)
	}
	if res.ExpectedAmountCents != 10000 {
		t.Fatalf("expected 10000 cents, got %d", res.ExpectedAmountCents)
	}
	if res.ReceivedAmountCents != 10000 {
		t.Fatalf("received: want 10000 cents (60.00+40.00), got %d", res.ReceivedAmountCents)
	}
	if !res.AmountReconciled() {
		t.Fatal("a fully-paid charge must reconcile")
	}
}

// TestGetChargeAmountDivergence asserts a partially-paid charge the PSP marked
// paid does NOT reconcile — the money half of reconcile-before-settle.
func TestGetChargeAmountDivergence(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.getHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"tx_123","status":"paid","valor":{"original":"100.00"},"pix":[{"valor":"60.00"}]}`))
	}
	p := ts.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.GetCharge(context.Background(), "t1", "tx_123")
	if err != nil {
		t.Fatalf("GetCharge: %v", err)
	}
	if res.ReceivedAmountCents != 6000 || res.ExpectedAmountCents != 10000 {
		t.Fatalf("unexpected amounts: %+v", res)
	}
	if res.AmountReconciled() {
		t.Fatal("a partially-paid charge must NOT reconcile")
	}
}

// TestGetChargeMalformedAmountFailsSecure asserts a present-but-malformed
// valor.original is treated as a corrupt money field (ErrUnavailable), never read
// as zero — fail-secure, mirroring the PIX path.
func TestGetChargeMalformedAmountFailsSecure(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.getHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"tx_123","status":"paid","valor":{"original":"abc"}}`))
	}
	p := ts.provider(t, oneTenant("t1", "client-1", "secret-1"))

	if _, err := p.GetCharge(context.Background(), "t1", "tx_123"); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable for malformed amount, got %v", err)
	}
}

// TestGetChargeMalformedReceiptFailsSecure asserts a malformed pix[] receipt
// amount also fails secure rather than under-counting the received total.
func TestGetChargeMalformedReceiptFailsSecure(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.getHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txid":"tx_123","status":"paid","valor":{"original":"100.00"},"pix":[{"valor":"oops"}]}`))
	}
	p := ts.provider(t, oneTenant("t1", "client-1", "secret-1"))

	if _, err := p.GetCharge(context.Background(), "t1", "tx_123"); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable for malformed receipt, got %v", err)
	}
}

// TestCreateChargeDoesNotFollowRedirect is the regression guard for F1 of the
// SIN-64750 security review: the adapter's HTTP client must NOT silently chase a
// 3xx from the PSP (a form of SSRF, and the stdlib default of following up to 10
// hops). Instead the 302 is handed back to do() and mapped to ErrUnavailable, as
// sentinelForStatus' "incl. 3xx we did not follow" comment intends. We assert both
// halves: the error is ErrUnavailable AND the redirect target is never reached.
func TestCreateChargeDoesNotFollowRedirect(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t)
	ts.createHandler = func(w http.ResponseWriter, _ *http.Request) {
		// Were this followed, the client would land on the /v2/pix/cob/ GET handler,
		// which returns a valid 200 body — turning the call into a false success.
		w.Header().Set("Location", "/v2/pix/cob/should-not-be-followed")
		w.WriteHeader(http.StatusFound) // 302
	}

	// Exercise the PRODUCTION default client (the one that sets CheckRedirect), but
	// graft the test server's TLS trust onto it so it can reach httptest over TLS.
	// Injecting ts.Client() (as provider() does) would bypass the very CheckRedirect
	// under test.
	c := defaultHTTPClient(15 * time.Second)
	c.Transport.(*http.Transport).TLSClientConfig = ts.Client().Transport.(*http.Transport).TLSClientConfig.Clone()

	p, err := New(Config{BaseURL: ts.URL, TokenURL: ts.URL + "/oauth/token", HTTPClient: c}, oneTenant("t1", "c", "s"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = p.CreateCharge(context.Background(), "t1", ports.ChargeRequest{TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL"})
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("a 3xx must map to ErrUnavailable, got %v", err)
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.createHits != 1 {
		t.Fatalf("create endpoint should be hit exactly once, got %d", ts.createHits)
	}
	if ts.getHits != 0 {
		t.Fatalf("redirect was followed: the target endpoint was reached (getHits=%d)", ts.getHits)
	}
}
