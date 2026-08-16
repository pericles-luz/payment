package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// account_key_mint_audit_test.go verifies SIN-69386 at the HTTP boundary: account-key
// emission leaves ONE account.key_mint audit entry regardless of which write surface
// performed it (JSON admin bootstrap + self-serve, and the HTML console), and the
// reject paths (missing idempotency key, unauthorized, CSRF-reject, self-account,
// unknown, replay) emit NO audit and NO secret. The audit sink is wired into the
// SHARED mint service, so a single sink observes both surfaces uniformly.

// recAudit records appended audit entries. It stands in for ports.AuditLog (the
// output port the mint service depends on); the durable behaviour is covered by the
// sqlite adapter tests.
type recAudit struct{ entries []audit.Entry }

func (r *recAudit) Append(_ context.Context, e audit.Entry) error {
	r.entries = append(r.entries, e)
	return nil
}

// mintOf returns the recorded mint entries (all of them are mints in these tests, but
// filtering keeps the assertions honest if the sink ever sees another action).
func (r *recAudit) mints() []audit.Entry {
	var out []audit.Entry
	for _, e := range r.entries {
		if e.Action() == audit.ActionMintAccountKey {
			out = append(out, e)
		}
	}
	return out
}

// --- JSON admin + self-serve surface ---

type akAuditFixture struct {
	handler http.Handler
	sink    *recAudit
	seeded  string
}

func newAKAuditFixture(t *testing.T) *akAuditFixture {
	t.Helper()
	keys := persistence.NewAccountKeyStore(system.Clock{})
	seeded, err := keys.PutKey(context.Background(), acctSeeded)
	if err != nil {
		t.Fatalf("seed key: %v", err)
	}
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{akTenantToken: "emp-x"},
		[]string{akAdminToken}, nil)
	sink := &recAudit{}
	cfg := httpadapter.Config{
		TenantAuth:         auth,
		AdminAuth:          auth,
		WebhookAuth:        auth,
		AccountKeyAuth:     keys,
		AccountKeySelector: true,
		AccountKeyMint: app.NewAccountKeyService(keys, system.Clock{},
			app.WithAccountKeyAudit(sink, system.IDProvider{})),
	}
	srv := httpadapter.NewServer(cfg)
	return &akAuditFixture{handler: srv.Router(), sink: sink, seeded: seeded}
}

// TestAdminBootstrapMintAudited: an admin bootstrap mint records one account-scoped
// entry attributing the admin operator; the tenant id is empty and no secret rides
// along.
func TestAdminBootstrapMintAudited(t *testing.T) {
	t.Parallel()
	f := newAKAuditFixture(t)
	rec := do(t, f.handler, http.MethodPost, adminMintPath("acct-verz"), akAdminToken,
		map[string]string{"Idempotency-Key": "boot-1"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	m := f.sink.mints()
	if len(m) != 1 {
		t.Fatalf("want 1 mint audit entry, got %d", len(m))
	}
	if m[0].AccountID() != "acct-verz" || m[0].TenantID() != "" {
		t.Fatalf("entry not account-scoped: acct=%q tenant=%q", m[0].AccountID(), m[0].TenantID())
	}
	if m[0].OperatorID() == "" {
		t.Fatalf("admin mint entry has no operator attribution")
	}
}

// TestSelfServeMintAudited: an Account self-rotating records one entry attributed to
// the account itself (operator "account:<id>"), covering the second JSON surface.
func TestSelfServeMintAudited(t *testing.T) {
	t.Parallel()
	f := newAKAuditFixture(t)
	rec := do(t, f.handler, http.MethodPost, akRotatePath, f.seeded,
		map[string]string{"Idempotency-Key": "idem-1"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	m := f.sink.mints()
	if len(m) != 1 {
		t.Fatalf("want 1 mint audit entry, got %d", len(m))
	}
	if m[0].AccountID() != acctSeeded {
		t.Fatalf("entry account = %q, want %q", m[0].AccountID(), acctSeeded)
	}
	if got := m[0].OperatorID(); got != "account:"+acctSeeded {
		t.Fatalf("self-serve operator = %q, want account:%s", got, acctSeeded)
	}
}

// TestSelfServeReplayNotAudited: a replay under the same Idempotency-Key mints
// nothing (409) and so records no second entry.
func TestSelfServeReplayNotAudited(t *testing.T) {
	t.Parallel()
	f := newAKAuditFixture(t)
	first := do(t, f.handler, http.MethodPost, akRotatePath, f.seeded,
		map[string]string{"Idempotency-Key": "idem-1"}, nil)
	if first.Code != http.StatusCreated {
		t.Fatalf("first mint = %d", first.Code)
	}
	// Authenticate with the freshly minted key (the seeded one is now invalid), replay
	// the same Idempotency-Key.
	var v mintView
	if err := json.Unmarshal(first.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode first mint: %v", err)
	}
	replay := do(t, f.handler, http.MethodPost, akRotatePath, v.Secret,
		map[string]string{"Idempotency-Key": "idem-1"}, nil)
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay = %d, want 409", replay.Code)
	}
	if n := len(f.sink.mints()); n != 1 {
		t.Fatalf("replay added an audit entry: got %d, want 1", n)
	}
}

// TestAdminMintRejectPathsNotAudited: a missing idempotency key (400) and an
// unauthorized caller (401) mint nothing and record nothing.
func TestAdminMintRejectPathsNotAudited(t *testing.T) {
	t.Parallel()
	f := newAKAuditFixture(t)

	miss := do(t, f.handler, http.MethodPost, adminMintPath("acct-verz"), akAdminToken, nil, nil)
	if miss.Code != http.StatusBadRequest {
		t.Fatalf("missing idem = %d, want 400", miss.Code)
	}
	unauth := do(t, f.handler, http.MethodPost, akRotatePath, "ak_not_a_real_key",
		map[string]string{"Idempotency-Key": "idem-x"}, nil)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unknown key = %d, want 401", unauth.Code)
	}
	if n := len(f.sink.mints()); n != 0 {
		t.Fatalf("reject paths recorded audit entries: got %d, want 0", n)
	}
}

// --- HTML console surface ---

type consoleAuditFixture struct {
	handler http.Handler
	sink    *recAudit
}

func newConsoleAuditFixture(t *testing.T) *consoleAuditFixture {
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
	sink := &recAudit{}
	cfg := httpadapter.Config{
		Console: console, UI: ui, AdminAuth: auth, TenantAuth: auth, WebhookAuth: auth,
		AccountKeyMint: app.NewAccountKeyService(keys, system.Clock{},
			app.WithAccountKeyAudit(sink, system.IDProvider{})),
	}
	srv := httpadapter.NewServer(cfg)
	return &consoleAuditFixture{handler: srv.Router(), sink: sink}
}

// TestConsoleMintAudited: a console mint records one account-scoped entry attributed
// to the console session operator — proving the console surface (which bypasses the
// ConsoleService audit envelope) is now covered by the shared mint-path audit.
func TestConsoleMintAudited(t *testing.T) {
	t.Parallel()
	f := newConsoleAuditFixture(t)
	csrf := acctCSRF(t, f.handler, adminToken)
	nonce := detailNonce(t, f.handler, "verz-1")

	rec := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken,
		url.Values{"idempotency_key": {nonce}}, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint = %d: %s", rec.Code, rec.Body.String())
	}
	m := f.sink.mints()
	if len(m) != 1 {
		t.Fatalf("want 1 console mint audit entry, got %d", len(m))
	}
	if m[0].AccountID() != "verz-1" || m[0].TenantID() != "" {
		t.Fatalf("entry not account-scoped: acct=%q tenant=%q", m[0].AccountID(), m[0].TenantID())
	}
	if m[0].OperatorID() == "" {
		t.Fatalf("console mint entry has no operator attribution")
	}
}

// TestConsoleMintRejectPathsNotAudited: CSRF-reject, replay (409), self-account (404)
// and unknown account (404) all mint nothing and record nothing.
func TestConsoleMintRejectPathsNotAudited(t *testing.T) {
	t.Parallel()

	t.Run("csrf reject", func(t *testing.T) {
		f := newConsoleAuditFixture(t)
		nonce := detailNonce(t, f.handler, "verz-1")
		rec := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken,
			url.Values{"idempotency_key": {nonce}}, nil)
		if rec.Code == http.StatusOK {
			t.Fatalf("no-csrf mint must not be 200")
		}
		if n := len(f.sink.mints()); n != 0 {
			t.Fatalf("csrf-rejected mint recorded audit: got %d, want 0", n)
		}
	})

	t.Run("replay", func(t *testing.T) {
		f := newConsoleAuditFixture(t)
		csrf := acctCSRF(t, f.handler, adminToken)
		form := url.Values{"idempotency_key": {detailNonce(t, f.handler, "verz-1")}}
		if first := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken, form, csrf); first.Code != http.StatusOK {
			t.Fatalf("first mint = %d", first.Code)
		}
		replay := consolePost(t, f.handler, "/console/accounts/verz-1/account-key", adminToken, form, csrf)
		if replay.Code != http.StatusConflict {
			t.Fatalf("replay = %d, want 409", replay.Code)
		}
		if n := len(f.sink.mints()); n != 1 {
			t.Fatalf("replay changed audit count: got %d, want 1", n)
		}
	})

	t.Run("self-account", func(t *testing.T) {
		f := newConsoleAuditFixture(t)
		csrf := acctCSRF(t, f.handler, adminToken)
		rec := consolePost(t, f.handler, "/console/accounts/"+selfAcctID+"/account-key", adminToken,
			url.Values{"idempotency_key": {"deadbeef"}}, csrf)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("self-account = %d, want 404", rec.Code)
		}
		if n := len(f.sink.mints()); n != 0 {
			t.Fatalf("self-account mint recorded audit: got %d, want 0", n)
		}
	})

	t.Run("unknown account", func(t *testing.T) {
		f := newConsoleAuditFixture(t)
		csrf := acctCSRF(t, f.handler, adminToken)
		rec := consolePost(t, f.handler, "/console/accounts/nope/account-key", adminToken,
			url.Values{"idempotency_key": {"deadbeef"}}, csrf)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("unknown account = %d, want 404", rec.Code)
		}
		if n := len(f.sink.mints()); n != 0 {
			t.Fatalf("unknown-account mint recorded audit: got %d, want 0", n)
		}
	})
}
