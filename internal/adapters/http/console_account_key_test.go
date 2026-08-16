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
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// console_account_key_test.go covers the console-plane Conta-key generation UI
// (SIN-69380): the admin console mints/rotates a real Conta's model (b) account key
// over the /console plane (session + CSRF), display-once. The browser NEVER touches
// the Bearer /admin/accounts/{id}/account-key route. A REAL in-memory account-key
// store backs the mint service (no DB mock), so a rotation actually produces a key
// that authenticates.

// akSecretRe lifts the plaintext account key rendered once into the success card.
var akSecretRe = regexp.MustCompile(`<code>(ak_[^<]+)</code>`)

type acctKeyFixture struct {
	handler http.Handler
	store   *persistence.Store
	keys    *persistence.AccountKeyStore
}

// selfAcctID is the derived self-account seeded alongside the real Conta so the
// self-account "no card / 404" behaviour can be exercised.
var selfAcctID = account.SelfAccountID("t-legacy")

// newAccountKeyFixture wires the console with the account plane AND (optionally) the
// account-key mint service, seeding a real Conta "verz-1" and a legacy self-account.
func newAccountKeyFixture(t *testing.T, mintWired bool) *acctKeyFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	if err := store.SaveAccount(context.Background(), account.Rehydrate("verz-1", "Verz", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := store.SaveAccount(context.Background(), account.Rehydrate(selfAcctID, "Legado", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed self account: %v", err)
	}
	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Accounts: store, Pricing: store, Ledger: store, Invoices: store,
		Audit: store, CredWriter: creds, CredReader: creds,
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
	keys := persistence.NewAccountKeyStore(system.Clock{})
	cfg := httpadapter.Config{
		Console: console, UI: ui, AdminAuth: auth, TenantAuth: auth, WebhookAuth: auth,
	}
	if mintWired {
		cfg.AccountKeyMint = app.NewAccountKeyService(keys, system.Clock{})
	}
	srv := httpadapter.NewServer(cfg)
	return &acctKeyFixture{handler: srv.Router(), store: store, keys: keys}
}

// detailNonce renders the account detail and lifts the per-render idempotency nonce
// out of the Chave-de-Conta form (exactly the token a browser resubmits).
func detailNonce(t *testing.T, h http.Handler, acctID string) string {
	t.Helper()
	page := consoleGet(t, h, "/console/accounts/"+acctID, adminToken)
	if page.Code != http.StatusOK {
		t.Fatalf("detail = %d: %s", page.Code, page.Body.String())
	}
	m := idemNonceRe.FindStringSubmatch(page.Body.String())
	if m == nil || m[1] == "" {
		t.Fatalf("no account-key nonce rendered in detail: %s", page.Body.String())
	}
	return m[1]
}

// TestConsoleAccountKeyCardVisibility: the card renders for a real Conta with the
// mint wired, and is hidden both for a legacy self-account and when the mint service
// is absent (degrade — no card rather than a dead button).
func TestConsoleAccountKeyCardVisibility(t *testing.T) {
	t.Parallel()
	f := newAccountKeyFixture(t, true)
	real := consoleGet(t, f.handler, "/console/accounts/verz-1", operatorToken)
	if real.Code != http.StatusOK || !strings.Contains(real.Body.String(), "Chave-de-Conta") {
		t.Fatalf("real Conta missing card = %d: %s", real.Code, real.Body.String())
	}
	if !strings.Contains(real.Body.String(), "/console/accounts/verz-1/account-key") {
		t.Fatalf("card missing mint form action: %s", real.Body.String())
	}
	// A legacy self-account has no account key → no card.
	self := consoleGet(t, f.handler, "/console/accounts/"+selfAcctID, operatorToken)
	if self.Code != http.StatusOK {
		t.Fatalf("self detail = %d", self.Code)
	}
	if strings.Contains(self.Body.String(), "account-key") {
		t.Fatalf("self-account must not render the account-key card: %s", self.Body.String())
	}
	// With no mint wired the card degrades away entirely.
	noMint := newAccountKeyFixture(t, false)
	nm := consoleGet(t, noMint.handler, "/console/accounts/verz-1", operatorToken)
	if strings.Contains(nm.Body.String(), "account-key") {
		t.Fatalf("card must be hidden when the mint service is not wired: %s", nm.Body.String())
	}
}

// TestConsoleAccountKeyMintShowsSecretOnce: an admin submits the form and gets the
// plaintext ONCE with a destructive-action banner; the minted key really
// authenticates as the Conta, and the response is marked no-store.
func TestConsoleAccountKeyMintShowsSecretOnce(t *testing.T) {
	t.Parallel()
	f := newAccountKeyFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)
	nonce := detailNonce(t, f.handler, "verz-1")

	rec := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken,
		url.Values{"idempotency_key": {nonce}}, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint = %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("mint response must be no-store, got %q", rec.Header().Get("Cache-Control"))
	}
	body := rec.Body.String()
	if !strings.Contains(body, "apenas") || !strings.Contains(body, "não pode ser recuperada") {
		t.Fatalf("missing display-once/destructive warning: %s", body)
	}
	m := akSecretRe.FindStringSubmatch(body)
	if m == nil || !accountkey.HasSecretShape(m[1]) {
		t.Fatalf("no valid account-key secret rendered once: %s", body)
	}
	if acct, ok := f.keys.AuthenticateAccountKey(context.Background(), m[1]); !ok || acct != "verz-1" {
		t.Fatalf("minted key does not authenticate to verz-1: acct=%q ok=%v", acct, ok)
	}
}

// TestConsoleAccountKeyCSRFRejected: a POST without the double-submit CSRF token is
// rejected (never mints), even with a valid admin bearer and a good nonce.
func TestConsoleAccountKeyCSRFRejected(t *testing.T) {
	t.Parallel()
	f := newAccountKeyFixture(t, true)
	nonce := detailNonce(t, f.handler, "verz-1")
	rec := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken,
		url.Values{"idempotency_key": {nonce}}, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("no-csrf mint must not be 200: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "ak_") {
		t.Fatalf("csrf-rejected response leaked a secret: %s", rec.Body.String())
	}
}

// TestConsoleAccountKeyReplayIs409: a double-submit of the SAME nonce (a double
// click / retry) collapses to 409 with NO secret in the body (display-once, never a
// second mint), while the first submission's key still authenticates.
func TestConsoleAccountKeyReplayIs409(t *testing.T) {
	t.Parallel()
	f := newAccountKeyFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)
	nonce := detailNonce(t, f.handler, "verz-1")
	form := url.Values{"idempotency_key": {nonce}}

	first := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken, form, csrf)
	if first.Code != http.StatusOK {
		t.Fatalf("first mint = %d: %s", first.Code, first.Body.String())
	}
	m := akSecretRe.FindStringSubmatch(first.Body.String())
	if m == nil {
		t.Fatalf("first mint rendered no secret: %s", first.Body.String())
	}
	firstSecret := m[1]

	replay := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken, form, csrf)
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay = %d, want 409: %s", replay.Code, replay.Body.String())
	}
	if strings.Contains(replay.Body.String(), "ak_") {
		t.Fatalf("409 replay leaked a secret: %s", replay.Body.String())
	}
	// No double-mint: the first key still authenticates.
	if acct, ok := f.keys.AuthenticateAccountKey(context.Background(), firstSecret); !ok || acct != "verz-1" {
		t.Fatalf("first key stopped working after replay: acct=%q ok=%v", acct, ok)
	}
}

// TestConsoleAccountKeyRotationInvalidatesPrevious: a fresh render (new nonce) mints
// a NEW key and immediately invalidates the previous one (destructive rotation).
func TestConsoleAccountKeyRotationInvalidatesPrevious(t *testing.T) {
	t.Parallel()
	f := newAccountKeyFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)

	first := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken,
		url.Values{"idempotency_key": {detailNonce(t, f.handler, "verz-1")}}, csrf)
	s1 := akSecretRe.FindStringSubmatch(first.Body.String())
	if s1 == nil {
		t.Fatalf("first mint rendered no secret: %s", first.Body.String())
	}
	second := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken,
		url.Values{"idempotency_key": {detailNonce(t, f.handler, "verz-1")}}, csrf)
	s2 := akSecretRe.FindStringSubmatch(second.Body.String())
	if s2 == nil {
		t.Fatalf("rotation rendered no secret: %s", second.Body.String())
	}
	if s1[1] == s2[1] {
		t.Fatalf("rotation returned the same secret")
	}
	if _, ok := f.keys.AuthenticateAccountKey(context.Background(), s1[1]); ok {
		t.Fatalf("previous key still authenticates after rotation")
	}
	if acct, ok := f.keys.AuthenticateAccountKey(context.Background(), s2[1]); !ok || acct != "verz-1" {
		t.Fatalf("rotated key does not authenticate: acct=%q ok=%v", acct, ok)
	}
}

// TestConsoleAccountKeyOperatorForbidden: a read-only operator cannot mint (the
// mutation group requires the full admin role).
func TestConsoleAccountKeyOperatorForbidden(t *testing.T) {
	t.Parallel()
	f := newAccountKeyFixture(t, true)
	csrf := acctCSRF(t, f.handler, operatorToken)
	rec := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", operatorToken,
		url.Values{"idempotency_key": {"deadbeef"}}, csrf)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator mint = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// TestConsoleAccountKeySelfAccountRejected: a crafted POST for a legacy self-account
// is refused (404) — account keys are for real Contas (defense-in-depth beyond the
// hidden card).
func TestConsoleAccountKeySelfAccountRejected(t *testing.T) {
	t.Parallel()
	f := newAccountKeyFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)
	rec := consolePost(t, f.handler, "/console/accounts/"+selfAcctID+"/account-key", adminToken,
		url.Values{"idempotency_key": {"deadbeef"}}, csrf)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("self-account mint = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

// TestConsoleAccountKeyUnknownAccount404: an unknown account id yields a clean 404.
func TestConsoleAccountKeyUnknownAccount404(t *testing.T) {
	t.Parallel()
	f := newAccountKeyFixture(t, true)
	csrf := acctCSRF(t, f.handler, adminToken)
	rec := consolePost(t, f.handler, "/console/accounts/nope/account-key", adminToken,
		url.Values{"idempotency_key": {"deadbeef"}}, csrf)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown account mint = %d, want 404", rec.Code)
	}
}

// TestConsoleAccountKeyServiceUnavailable: with the mint service not wired the route
// fails closed (503) rather than panicking or pretending to mint.
func TestConsoleAccountKeyServiceUnavailable(t *testing.T) {
	t.Parallel()
	f := newAccountKeyFixture(t, false)
	csrf := acctCSRF(t, f.handler, adminToken)
	rec := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken,
		url.Values{"idempotency_key": {"deadbeef"}}, csrf)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("mint without service = %d, want 503: %s", rec.Code, rec.Body.String())
	}
}
