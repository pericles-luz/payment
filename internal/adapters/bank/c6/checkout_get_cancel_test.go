package c6

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// checkoutRWServer is a minimal C6 double for the checkout reconcile (GET
// /v1/checkouts/{id}) and cancel (PUT /v1/checkouts/{id}/cancel) operations plus the
// OAuth2 token endpoint, backed by httptest TLS. Each operation defaults to a happy
// path overridable per test. It is intentionally separate from productServer so these
// tests do not touch shared scaffolding.
type checkoutRWServer struct {
	*httptest.Server
	tokenHits int
	lastAuth  string
	get       http.HandlerFunc
	cancel    http.HandlerFunc
}

func newCheckoutRWServer(t *testing.T) *checkoutRWServer {
	t.Helper()
	cs := &checkoutRWServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		cs.tokenHits++
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("GET /v1/checkouts/{id}", func(w http.ResponseWriter, r *http.Request) {
		cs.lastAuth = r.Header.Get("Authorization")
		if cs.get != nil {
			cs.get(w, r)
			return
		}
		// Real reconcile (GET 200): the full `checkout` schema — id, status, decimal
		// amount (reais) and url. No captured/received amount (captured_amount is
		// "EM BREVE"), so the read cannot reconcile by captured value.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chk_1","status":"PAID","amount":15.00,"url":"https://checkout.c6bank.info/chk_1"}`))
	})
	mux.HandleFunc("PUT /v1/checkouts/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		cs.lastAuth = r.Header.Get("Authorization")
		if cs.cancel != nil {
			cs.cancel(w, r)
			return
		}
		// Real cancel: 204 No Content, no body.
		w.WriteHeader(http.StatusNoContent)
	})
	cs.Server = httptest.NewTLSServer(mux)
	t.Cleanup(cs.Close)
	return cs
}

func (cs *checkoutRWServer) provider(t *testing.T, creds ports.CredentialStore) *Provider {
	t.Helper()
	p, err := New(Config{BaseURL: cs.URL, TokenURL: cs.URL + "/oauth/token", HTTPClient: cs.Client()}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// TestGetCheckoutSessionSuccess asserts the reconcile read maps id/status/amount from
// the real `checkout` schema and attaches the per-tenant bearer. C6 does not yet
// return a captured amount (captured_amount is "EM BREVE"), so ReceivedAmountCents is
// zero and AmountReconciled() is false — fail-safe for threat W3 (a checkout is never
// settled for an unverified captured amount). Settlement-by-captured-amount is a
// follow-up once C6 GA's captured_amount (settlement path, SIN-65726).
func TestGetCheckoutSessionSuccess(t *testing.T) {
	t.Parallel()
	cs := newCheckoutRWServer(t)
	p := cs.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.GetCheckoutSession(context.Background(), "t1", "chk_1")
	if err != nil {
		t.Fatalf("GetCheckoutSession: %v", err)
	}
	if res.SessionID != "chk_1" || res.Status != "PAID" || res.AmountCents != 1500 || res.ReceivedAmountCents != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.AmountReconciled() {
		t.Fatalf("no captured amount is available yet — reconcile must stay false (fail-safe): %+v", res)
	}
	if cs.lastAuth != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", cs.lastAuth)
	}
}

// TestGetCheckoutSessionNotFound asserts a 404 surfaces as ErrNotFound.
func TestGetCheckoutSessionNotFound(t *testing.T) {
	t.Parallel()
	cs := newCheckoutRWServer(t)
	cs.get = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND"}`))
	}
	p := cs.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.GetCheckoutSession(context.Background(), "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// TestGetCheckoutSessionRejectsUntrustedRedirect asserts a reconcile read that returns
// a non-https redirect target fails closed (ErrUnavailable) rather than handing the
// caller an open-redirect — defense-in-depth identical to the create path.
func TestGetCheckoutSessionRejectsUntrustedRedirect(t *testing.T) {
	t.Parallel()
	cs := newCheckoutRWServer(t)
	cs.get = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chk_1","status":"IN PROGRESS","url":"http://evil/chk_1","amount":15.00}`))
	}
	p := cs.provider(t, oneTenant("t1", "c", "s"))
	res, err := p.GetCheckoutSession(context.Background(), "t1", "chk_1")
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("untrusted redirect must map to ErrUnavailable, got %v", err)
	}
	if res != (ports.CheckoutResult{}) {
		t.Fatalf("result must be empty on untrusted redirect, got %+v", res)
	}
}

// TestCancelCheckoutSessionSuccess asserts cancel maps the cancelled state; a cancelled
// session carries no redirect URL so the redirect guard is not triggered.
func TestCancelCheckoutSessionSuccess(t *testing.T) {
	t.Parallel()
	cs := newCheckoutRWServer(t)
	p := cs.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.CancelCheckoutSession(context.Background(), "t1", "chk_1")
	if err != nil {
		t.Fatalf("CancelCheckoutSession: %v", err)
	}
	// Cancel returns 204 (no body); the adapter synthesizes the cancelled state.
	if res.SessionID != "chk_1" || res.Status != "CANCELLED" || res.RedirectURL != "" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if cs.lastAuth != "Bearer tok-client-1" {
		t.Fatalf("bearer not attached: %q", cs.lastAuth)
	}
}

// TestCancelCheckoutSessionError asserts a non-2xx cancel maps to the domain error.
func TestCancelCheckoutSessionError(t *testing.T) {
	t.Parallel()
	cs := newCheckoutRWServer(t)
	cs.cancel = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"X"}`))
	}
	p := cs.provider(t, oneTenant("t1", "c", "s"))
	if _, err := p.CancelCheckoutSession(context.Background(), "t1", "chk_1"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}

// TestCheckoutRWMissingCredential asserts the get/cancel ops resolve the tenant
// credential first: an unknown tenant is ErrNotFound and the token endpoint is never
// hit (per-tenant isolation).
func TestCheckoutRWMissingCredential(t *testing.T) {
	t.Parallel()
	cs := newCheckoutRWServer(t)
	p := cs.provider(t, &fakeCreds{creds: map[string]ports.BankCredential{}})
	if _, err := p.GetCheckoutSession(context.Background(), "unknown", "s"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("get: want ErrNotFound, got %v", err)
	}
	if _, err := p.CancelCheckoutSession(context.Background(), "unknown", "s"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cancel: want ErrNotFound, got %v", err)
	}
	if cs.tokenHits != 0 {
		t.Fatalf("token endpoint must not be hit without a credential, hits=%d", cs.tokenHits)
	}
}
