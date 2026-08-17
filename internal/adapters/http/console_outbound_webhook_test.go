package http_test

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
)

// console_outbound_webhook_test.go covers the console-plane per-Conta outbound webhook
// config UI (SIN-69490, F0 of SIN-69486): the "Webhook de saída" card + set/rotate/
// remove over /console (session + CSRF), the signing secret shown display-once, and the
// dark flag PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK gating card + routes.

// whSecretRe lifts the signing secret rendered once into the result card.
var whSecretRe = regexp.MustCompile(`<code>(whsec_[^<]+)</code>`)

type owFixture struct {
	handler  http.Handler
	store    *persistence.Store
	webhooks *persistence.OutboundWebhookStore
}

// owSelfAcctID is a legacy self-account seeded alongside the real Conta so the
// self-account "no card / 404" behaviour can be exercised.
var owSelfAcctID = account.SelfAccountID("t-legacy")

func newOutboundWebhookFixture(t *testing.T, flagOn bool) *owFixture {
	t.Helper()
	store := persistence.NewStore()
	webhooks := persistence.NewOutboundWebhookStore()
	if err := store.SaveAccount(context.Background(), account.Rehydrate("verz-1", "Verz", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := store.SaveAccount(context.Background(), account.Rehydrate(owSelfAcctID, "Legado", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed self account: %v", err)
	}
	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Accounts: store, Pricing: store, Ledger: store, Invoices: store,
		Audit: store, OutboundWebhooks: webhooks,
		Clock: fixedClock{}, IDs: &incIDs{},
	})
	ui, err := adminweb.New()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, map[string]httpadapter.Role{
		adminToken:    httpadapter.RoleAdmin,
		operatorToken: httpadapter.RoleOperator,
	}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Console: console, UI: ui, AdminAuth: auth, TenantAuth: auth, WebhookAuth: auth,
		AccountOutboundWebhook: flagOn,
	})
	return &owFixture{handler: srv.Router(), store: store, webhooks: webhooks}
}

// TestOutboundWebhookFlagOff: with the flag off the card is hidden and the mutation
// routes are not registered (rollback = config flip).
func TestOutboundWebhookFlagOff(t *testing.T) {
	t.Parallel()
	f := newOutboundWebhookFixture(t, false)
	detail := consoleGet(t, f.handler, "/console/accounts/verz-1", operatorToken)
	if detail.Code != http.StatusOK {
		t.Fatalf("detail = %d", detail.Code)
	}
	if strings.Contains(detail.Body.String(), "Webhook de saída") {
		t.Errorf("card must be hidden when the flag is off: %s", detail.Body.String())
	}
	// The set route is not registered → not a 200.
	csrf := acctCSRF(t, f.handler, adminToken)
	rec := consolePost(t, f.handler, "/console/accounts/verz-1/webhook", adminToken,
		url.Values{"url": {"https://e.example.com/h"}}, csrf)
	if rec.Code == http.StatusOK {
		t.Errorf("set route must be unregistered when flag off; got 200")
	}
}

// TestOutboundWebhookCardVisibility: with the flag on the card renders for a real
// Conta and is hidden for a legacy self-account.
func TestOutboundWebhookCardVisibility(t *testing.T) {
	t.Parallel()
	f := newOutboundWebhookFixture(t, true)
	real := consoleGet(t, f.handler, "/console/accounts/verz-1", operatorToken)
	if real.Code != http.StatusOK || !strings.Contains(real.Body.String(), "Webhook de saída") {
		t.Fatalf("real Conta missing card = %d: %s", real.Code, real.Body.String())
	}
	if !strings.Contains(real.Body.String(), "/console/accounts/verz-1/webhook") {
		t.Fatalf("card missing set form action: %s", real.Body.String())
	}
	self := consoleGet(t, f.handler, "/console/accounts/"+owSelfAcctID, operatorToken)
	if self.Code != http.StatusOK {
		t.Fatalf("self detail = %d", self.Code)
	}
	if strings.Contains(self.Body.String(), "Webhook de saída") {
		t.Fatalf("self-account must not render the webhook card: %s", self.Body.String())
	}
}

// TestOutboundWebhookSetShowsSecretOnce: setting the endpoint the FIRST time returns
// the signing secret exactly once with a no-store header, and persists the config.
func TestOutboundWebhookSetShowsSecretOnce(t *testing.T) {
	t.Parallel()
	f := newOutboundWebhookFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)
	rec := consolePost(t, f.handler, "/console/accounts/verz-1/webhook", adminToken,
		url.Values{"url": {"https://verz.example.com/hook"}, "enabled": {"on"}}, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("set = %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q; want no-store", rec.Header().Get("Cache-Control"))
	}
	m := whSecretRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no signing secret rendered: %s", rec.Body.String())
	}
	// The config really persisted with that secret + url + enabled.
	got, err := f.webhooks.GetOutboundWebhook(context.Background(), "verz-1")
	if err != nil {
		t.Fatalf("persisted get: %v", err)
	}
	if got.SigningSecret() != m[1] || got.URL() != "https://verz.example.com/hook" || !got.Enabled() {
		t.Errorf("persisted config mismatch: %+v (secret shown %q)", got, m[1])
	}
}

// TestOutboundWebhookUpdateNoSecret: updating an existing endpoint does NOT re-show
// the secret (write-only) and returns a card + toast.
func TestOutboundWebhookUpdateNoSecret(t *testing.T) {
	t.Parallel()
	f := newOutboundWebhookFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)
	if r := consolePost(t, f.handler, "/console/accounts/verz-1/webhook", adminToken,
		url.Values{"url": {"https://verz.example.com/hook"}, "enabled": {"on"}}, csrf); r.Code != http.StatusOK {
		t.Fatalf("initial set = %d", r.Code)
	}
	before, _ := f.webhooks.GetOutboundWebhook(context.Background(), "verz-1")
	// Update: change URL, disable, and NO enabled field submitted.
	upd := consolePost(t, f.handler, "/console/accounts/verz-1/webhook", adminToken,
		url.Values{"url": {"https://verz.example.com/hook2"}}, csrf)
	if upd.Code != http.StatusOK {
		t.Fatalf("update = %d: %s", upd.Code, upd.Body.String())
	}
	if whSecretRe.MatchString(upd.Body.String()) {
		t.Errorf("update must NOT re-show the signing secret: %s", upd.Body.String())
	}
	after, _ := f.webhooks.GetOutboundWebhook(context.Background(), "verz-1")
	if after.URL() != "https://verz.example.com/hook2" || after.Enabled() {
		t.Errorf("update not applied: %+v", after)
	}
	if after.SigningSecret() != before.SigningSecret() {
		t.Error("update changed the signing secret; it must be preserved")
	}
}

// TestOutboundWebhookSetValidationError: a non-https URL re-renders the card inline
// (422) with the field error and NO secret; nothing is persisted.
func TestOutboundWebhookSetValidationError(t *testing.T) {
	t.Parallel()
	f := newOutboundWebhookFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)
	rec := consolePost(t, f.handler, "/console/accounts/verz-1/webhook", adminToken,
		url.Values{"url": {"http://insecure"}, "enabled": {"on"}}, csrf)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad url = %d, want 422: %s", rec.Code, rec.Body.String())
	}
	if whSecretRe.MatchString(rec.Body.String()) {
		t.Error("no secret should be shown on validation failure")
	}
	if _, err := f.webhooks.GetOutboundWebhook(context.Background(), "verz-1"); err == nil {
		t.Error("nothing should persist on validation failure")
	}
}

// TestOutboundWebhookRotate: rotate mints a fresh secret (different from the first),
// shown display-once with no-store.
func TestOutboundWebhookRotate(t *testing.T) {
	t.Parallel()
	f := newOutboundWebhookFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)
	setRec := consolePost(t, f.handler, "/console/accounts/verz-1/webhook", adminToken,
		url.Values{"url": {"https://verz.example.com/hook"}, "enabled": {"on"}}, csrf)
	first := whSecretRe.FindStringSubmatch(setRec.Body.String())
	if first == nil {
		t.Fatalf("no first secret: %s", setRec.Body.String())
	}
	rot := consolePost(t, f.handler, "/console/accounts/verz-1/webhook/secret", adminToken, nil, csrf)
	if rot.Code != http.StatusOK {
		t.Fatalf("rotate = %d: %s", rot.Code, rot.Body.String())
	}
	if rot.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("rotate Cache-Control = %q; want no-store", rot.Header().Get("Cache-Control"))
	}
	second := whSecretRe.FindStringSubmatch(rot.Body.String())
	if second == nil {
		t.Fatalf("no rotated secret: %s", rot.Body.String())
	}
	if first[1] == second[1] {
		t.Error("rotate returned the same secret")
	}
}

// TestOutboundWebhookRemove: removing the config swaps the empty-state card.
func TestOutboundWebhookRemove(t *testing.T) {
	t.Parallel()
	f := newOutboundWebhookFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)
	if r := consolePost(t, f.handler, "/console/accounts/verz-1/webhook", adminToken,
		url.Values{"url": {"https://verz.example.com/hook"}, "enabled": {"on"}}, csrf); r.Code != http.StatusOK {
		t.Fatalf("set = %d", r.Code)
	}
	rec := consoleMethod(t, f.handler, http.MethodDelete, "/console/accounts/verz-1/webhook", adminToken, nil, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := f.webhooks.GetOutboundWebhook(context.Background(), "verz-1"); err == nil {
		t.Error("config should be gone after remove")
	}
}

// TestOutboundWebhookSelfAccount404: a crafted mutation against a legacy self-account
// is refused with a clean 404 (the card is hidden; the service guards regardless).
func TestOutboundWebhookSelfAccount404(t *testing.T) {
	t.Parallel()
	f := newOutboundWebhookFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)
	rec := consolePost(t, f.handler, "/console/accounts/"+owSelfAcctID+"/webhook", adminToken,
		url.Values{"url": {"https://e.example.com/h"}}, csrf)
	if rec.Code != http.StatusNotFound {
		t.Errorf("self-account set = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

// TestOutboundWebhookCSRFRequired: a mutation without the CSRF double-submit is
// rejected (session + CSRF inherited from the admin mutation group).
func TestOutboundWebhookCSRFRequired(t *testing.T) {
	t.Parallel()
	f := newOutboundWebhookFixture(t, true)
	rec := consolePost(t, f.handler, "/console/accounts/verz-1/webhook", adminToken,
		url.Values{"url": {"https://e.example.com/h"}}, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("missing CSRF = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// TestOutboundWebhookReadRequiresRole: the read card fragment admits Operator+Admin.
func TestOutboundWebhookReadFragment(t *testing.T) {
	t.Parallel()
	f := newOutboundWebhookFixture(t, true)
	rec := consoleGet(t, f.handler, "/console/accounts/verz-1/webhook", operatorToken)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Webhook de saída") {
		t.Fatalf("read fragment = %d: %s", rec.Code, rec.Body.String())
	}
}
