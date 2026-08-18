package http_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
)

// fakeInflowRegistrar records the tenants it was asked to register, proving the
// self-serve write handlers invoke the in-flow C6 registration (SIN-69560 / F2)
// AFTER a successful write. It never errors (best-effort by contract).
type fakeInflowRegistrar struct {
	mu      sync.Mutex
	tenants []string
}

func (f *fakeInflowRegistrar) TryRegister(_ context.Context, tenantID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants = append(f.tenants, tenantID)
}

func (f *fakeInflowRegistrar) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.tenants...)
}

// inflowFixture wires a tenant-plane server with the self-serve credential intake ON
// and a fake in-flow registrar, so a credential PUT can be observed to trigger the
// registration attempt bound to the authenticated tenant.
type inflowFixture struct {
	handler http.Handler
	tenantA string
	tokenA  string
	reg     *fakeInflowRegistrar
}

func newInflowFixture(t *testing.T) *inflowFixture {
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
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	const tokenA = "inflow-tok-a"
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tokenA: tn.ID()}, []string{adminToken}, nil)
	reg := &fakeInflowRegistrar{}
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:             app.NewChargeService(deps),
		Admin:               admin,
		Webhooks:            app.NewWebhookService(deps),
		TenantAuth:          auth,
		AdminAuth:           auth,
		WebhookAuth:         auth,
		SelfServeCredIntake: true,
		WebhookRegistrar:    reg,
	})
	return &inflowFixture{handler: srv.Router(), tenantA: tn.ID(), tokenA: tokenA, reg: reg}
}

// TestSelfServeCredentialTriggersInflowRegistration proves a successful self-serve
// credential PUT invokes the in-flow C6 webhook registration with the AUTHENTICATED
// tenant (from the token, never the body), and that the write still returns 200 — the
// registration is a best-effort side effect, not a precondition of the response.
func TestSelfServeCredentialTriggersInflowRegistration(t *testing.T) {
	t.Parallel()
	f := newInflowFixture(t)

	rec := do(t, f.handler, http.MethodPut, "/v1/bank-credential", f.tokenA, nil,
		map[string]any{"bank": "c6", "client_id": "cid-a", "secret": "shh"})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	seen := f.reg.seen()
	if len(seen) != 1 || seen[0] != f.tenantA {
		t.Fatalf("in-flow registration tenants = %v, want [%s]", seen, f.tenantA)
	}
}

// TestSelfServeCredentialRejectedSkipsRegistration proves a REJECTED write (invalid
// bank → 400) does NOT trigger the registration — the hook fires only after a
// successful write.
func TestSelfServeCredentialRejectedSkipsRegistration(t *testing.T) {
	t.Parallel()
	f := newInflowFixture(t)

	rec := do(t, f.handler, http.MethodPut, "/v1/bank-credential", f.tokenA, nil,
		map[string]any{"bank": "nubank", "client_id": "cid-a", "secret": "shh"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for non-allow-listed bank, got %d (%s)", rec.Code, rec.Body.String())
	}
	if seen := f.reg.seen(); len(seen) != 0 {
		t.Fatalf("rejected write must not trigger registration, got %v", seen)
	}
}
