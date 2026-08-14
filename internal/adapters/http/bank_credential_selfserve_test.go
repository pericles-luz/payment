package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// selfServeFixture wires a tenant-plane server with the self-serve credential
// intake enabled, a real credential store and a real (in-memory) audit log, plus a
// second tenant to prove cross-tenant isolation. tokenA/tokenB authenticate the two
// tenants; there is NO admin-addressable selector in the self-serve contract.
type selfServeFixture struct {
	handler          http.Handler
	tenantA, tenantB string
	tokenA, tokenB   string
	creds            *secret.Store
	audit            *auditlog.Log
}

const (
	selfTokenA = "self-tok-a"
	selfTokenB = "self-tok-b"
)

// newSelfServeFixtureFlag builds the fixture with the intake flag set as given, so
// the same wiring covers both the enabled behaviour and the flag-off inert case.
func newSelfServeFixtureFlag(t *testing.T, enabled bool) *selfServeFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	log := auditlog.NewLog()
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store, Processed: store,
		Bus: inmemory.NewBus(), Bank: stub, Credentials: creds, CredWriter: creds,
		Audit: log, Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	mk := func(name string) string {
		tn, err := admin.CreateTenant(context.Background(), name)
		if err != nil {
			t.Fatalf("seed tenant %s: %v", name, err)
		}
		return tn.ID()
	}
	tenantA, tenantB := mk("Acme"), mk("Globex")
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{selfTokenA: tenantA, selfTokenB: tenantB},
		[]string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:             app.NewChargeService(deps),
		Admin:               admin,
		Webhooks:            app.NewWebhookService(deps),
		TenantAuth:          auth,
		AdminAuth:           auth,
		WebhookAuth:         auth,
		SelfServeCredIntake: enabled,
	})
	return &selfServeFixture{
		handler: srv.Router(), tenantA: tenantA, tenantB: tenantB,
		tokenA: selfTokenA, tokenB: selfTokenB, creds: creds, audit: log,
	}
}

func newSelfServeFixture(t *testing.T) *selfServeFixture { return newSelfServeFixtureFlag(t, true) }

const selfServePath = "/v1/bank-credential"

// TestSelfServeCredentialWritesOwnTenant is the happy path: a tenant PUTs its own
// credential, gets 200 with a secret-free view, and the credential lands under
// (its tenant, c6) — the tenant coming from the token, not any request field.
func TestSelfServeCredentialWritesOwnTenant(t *testing.T) {
	t.Parallel()
	f := newSelfServeFixture(t)
	const secretVal = "do-not-echo-me"

	rec := do(t, f.handler, http.MethodPut, selfServePath, f.tokenA, nil,
		map[string]any{"bank": "c6", "client_id": "cid-a", "secret": secretVal})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, secretVal) {
		t.Fatalf("response leaked the secret: %s", body)
	}
	var view struct {
		TenantID string `json:"tenant_id"`
		Bank     string `json:"bank"`
		ClientID string `json:"client_id"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if view.TenantID != f.tenantA || view.Bank != ports.BankIDC6 || view.Status != "ok" {
		t.Fatalf("unexpected view: %+v", view)
	}
	got, err := f.creds.GetBankCredential(context.Background(), f.tenantA, ports.BankIDC6)
	if err != nil {
		t.Fatalf("read stored credential: %v", err)
	}
	if got.ClientID != "cid-a" || got.Secret != secretVal {
		t.Fatalf("credential not stored under (A, c6): %+v", got)
	}
	// The write emitted a credential.set audit entry stamped origin=self-serve.
	entries := f.audit.Entries()
	last := entries[len(entries)-1]
	if last.Action() != audit.ActionSetBankCredential || last.Origin() != audit.OriginSelfServe {
		t.Fatalf("audit entry = action %q origin %q, want credential.set/self-serve", last.Action(), last.Origin())
	}
	if last.TenantID() != f.tenantA {
		t.Fatalf("audit tenant = %q, want %q", last.TenantID(), f.tenantA)
	}
}

// TestSelfServeCredentialDefaultsBankToC6 pins that an empty bank resolves to c6
// (retro-compat with the single-bank default), matching the admin path.
func TestSelfServeCredentialDefaultsBankToC6(t *testing.T) {
	t.Parallel()
	f := newSelfServeFixture(t)
	rec := do(t, f.handler, http.MethodPut, selfServePath, f.tokenA, nil,
		map[string]any{"client_id": "cid-legacy", "secret": "shh"})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := f.creds.GetBankCredential(context.Background(), f.tenantA, ports.BankIDC6); err != nil {
		t.Fatalf("default-bank credential not stored: %v", err)
	}
}

// TestSelfServeCredentialRejectsNonC6 pins the Q4 dedicated allow-list: a bank
// outside {c6} is rejected with 400 and NOTHING is written or echoed — even a bank
// the platform-wide known set might one day include.
func TestSelfServeCredentialRejectsNonC6(t *testing.T) {
	t.Parallel()
	f := newSelfServeFixture(t)
	rec := do(t, f.handler, http.MethodPut, selfServePath, f.tokenA, nil,
		map[string]any{"bank": "nubank", "client_id": "cid", "secret": "shh"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for non-c6 bank, got %d (%s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "nubank") {
		t.Fatalf("400 response echoed the input bank: %s", body)
	}
	if _, err := f.creds.GetBankCredential(context.Background(), f.tenantA, "nubank"); err == nil {
		t.Fatal("non-c6 credential must not be stored")
	}
}

// TestSelfServeCredentialRequiresAuth pins deny-by-default: no token → 401, and an
// admin token (wrong audience for the tenant plane) → 401. The credential is a
// tenant-plane self-service, never reachable without a tenant identity.
func TestSelfServeCredentialRequiresAuth(t *testing.T) {
	t.Parallel()
	f := newSelfServeFixture(t)
	body := map[string]any{"bank": "c6", "client_id": "cid", "secret": "shh"}
	if rec := do(t, f.handler, http.MethodPut, selfServePath, "", nil, body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", rec.Code)
	}
	if rec := do(t, f.handler, http.MethodPut, selfServePath, adminToken, nil, body); rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin token on tenant plane: want 401, got %d", rec.Code)
	}
}

// TestSelfServeCredentialCrossTenantIsolation is the server-enforced isolation
// regression: tenant A's token can only ever write (A, c6). There is NO parameter
// in the contract to address tenant B, so a write with A's token leaves B's
// credential absent — the whole broken-access-control class is designed out.
func TestSelfServeCredentialCrossTenantIsolation(t *testing.T) {
	t.Parallel()
	f := newSelfServeFixture(t)

	rec := do(t, f.handler, http.MethodPut, selfServePath, f.tokenA, nil,
		map[string]any{"bank": "c6", "client_id": "cid-a", "secret": "a-secret"})
	if rec.Code != http.StatusOK {
		t.Fatalf("A write: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	// A wrote its own credential.
	if _, err := f.creds.GetBankCredential(context.Background(), f.tenantA, ports.BankIDC6); err != nil {
		t.Fatalf("A credential missing: %v", err)
	}
	// B's credential was NOT touched by A's request (no selector exists to address B).
	if _, err := f.creds.GetBankCredential(context.Background(), f.tenantB, ports.BankIDC6); err == nil {
		t.Fatal("isolation breach: A's write created a credential for B")
	}
	// The audit entry attributes the write to A, not B.
	entries := f.audit.Entries()
	last := entries[len(entries)-1]
	if last.TenantID() != f.tenantA {
		t.Fatalf("audit attributed write to %q, want A (%q)", last.TenantID(), f.tenantA)
	}
}

// TestSelfServeCredentialCreateEqualsRotate is the Q5 no-oracle assertion: the
// response to a CREATE and to a subsequent ROTATE (overwrite) with the same request
// is byte-identical — nothing reveals whether a credential already existed.
func TestSelfServeCredentialCreateEqualsRotate(t *testing.T) {
	t.Parallel()
	f := newSelfServeFixture(t)
	body := map[string]any{"bank": "c6", "client_id": "cid-a", "secret": "rotate-me"}

	create := do(t, f.handler, http.MethodPut, selfServePath, f.tokenA, nil, body)
	rotate := do(t, f.handler, http.MethodPut, selfServePath, f.tokenA, nil, body)
	if create.Code != http.StatusOK || rotate.Code != http.StatusOK {
		t.Fatalf("create=%d rotate=%d, want both 200", create.Code, rotate.Code)
	}
	if create.Body.String() != rotate.Body.String() {
		t.Fatalf("create/rotate responses differ (oracle):\n create=%q\n rotate=%q", create.Body.String(), rotate.Body.String())
	}
	if strings.Contains(rotate.Body.String(), "rotate-me") {
		t.Fatalf("response leaked the secret: %s", rotate.Body.String())
	}
}

// TestSelfServeCredentialRateLimited pins the Q1 dedicated inbound limiter: a flood
// past the small burst trips 429 with a Retry-After header. The bucket is per
// tenant, so the limit is the intake's own, not the shared tenant-plane budget.
func TestSelfServeCredentialRateLimited(t *testing.T) {
	t.Parallel()
	f := newSelfServeFixture(t)
	body := map[string]any{"bank": "c6", "client_id": "cid-a", "secret": "s"}
	var limitedAt = -1
	for i := 0; i < 20; i++ {
		rec := do(t, f.handler, http.MethodPut, selfServePath, f.tokenA, nil, body)
		if i == 0 && rec.Code == http.StatusTooManyRequests {
			t.Fatal("first request must not be rate-limited")
		}
		if rec.Code == http.StatusTooManyRequests {
			if ra := rec.Header().Get("Retry-After"); ra == "" {
				t.Fatalf("429 missing Retry-After header")
			}
			limitedAt = i
			break
		}
	}
	if limitedAt < 1 {
		t.Fatalf("expected a 429 within the burst, tripped at %d", limitedAt)
	}
}

// TestSelfServeCredentialFlagOffInert pins the rollback path: with the flag off the
// route is not registered, so even a valid tenant token gets 404 — the feature is
// fully inert and nothing is written.
func TestSelfServeCredentialFlagOffInert(t *testing.T) {
	t.Parallel()
	f := newSelfServeFixtureFlag(t, false)
	rec := do(t, f.handler, http.MethodPut, selfServePath, f.tokenA, nil,
		map[string]any{"bank": "c6", "client_id": "cid", "secret": "s"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("flag off: want 404 (route absent), got %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := f.creds.GetBankCredential(context.Background(), f.tenantA, ports.BankIDC6); err == nil {
		t.Fatal("flag off must write nothing")
	}
}
