package http_test

import (
	"context"
	"net/http"
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

// adminRegFixture wires an admin-plane server with BOTH credential and certificate
// vaults plus a fake in-flow registrar, so an admin Bearer cred/cert PUT can be observed
// to trigger the C6 webhook registration bound to the target tenant (SIN-69588 / B3).
type adminRegFixture struct {
	handler http.Handler
	tenant  string
	reg     *fakeInflowRegistrar
}

func newAdminRegFixture(t *testing.T) *adminRegFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	certs := secret.NewCertStore()
	stub := bank.NewStubProvider(creds)
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store, Processed: store,
		Bus: inmemory.NewBus(), Bank: stub, Credentials: creds, CredWriter: creds,
		CertWriter: certs, Audit: auditlog.NewLog(), Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	auth := httpadapter.NewStaticTokenAuth(nil, []string{adminToken}, nil)
	reg := &fakeInflowRegistrar{}
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:          app.NewChargeService(deps),
		Admin:            admin,
		Webhooks:         app.NewWebhookService(deps),
		TenantAuth:       auth,
		AdminAuth:        auth,
		WebhookAuth:      auth,
		WebhookRegistrar: reg,
	})
	return &adminRegFixture{handler: srv.Router(), tenant: tn.ID(), reg: reg}
}

// TestAdminCredentialTriggersInflowRegistration proves the ADMIN Bearer credential
// intake (PUT /admin/tenants/{id}/bank-credential) invokes the in-flow C6 webhook
// registration after a successful write, exactly like the self-serve path (SIN-69588 /
// B3). Prod creds are provisioned through this admin plane per the runbook, so without
// this hook the go-live registration path was uncovered.
func TestAdminCredentialTriggersInflowRegistration(t *testing.T) {
	t.Parallel()
	f := newAdminRegFixture(t)

	rec := do(t, f.handler, http.MethodPut, "/admin/tenants/"+f.tenant+"/bank-credential", adminToken, nil,
		map[string]any{"bank": "c6", "client_id": "cid-a", "secret": "shh"})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if seen := f.reg.seen(); len(seen) != 1 || seen[0] != f.tenant {
		t.Fatalf("admin credential registration tenants = %v, want [%s]", seen, f.tenant)
	}
}

// TestAdminCertificateTriggersInflowRegistration proves the ADMIN Bearer certificate
// intake also invokes the registration after a successful write (SIN-69588 / B3) — a
// cert write can complete the mTLS half needed to reach C6.
func TestAdminCertificateTriggersInflowRegistration(t *testing.T) {
	t.Parallel()
	f := newAdminRegFixture(t)
	certPEM, keyPEM := httpCertKeyPEM(t)

	rec := do(t, f.handler, http.MethodPut, "/admin/tenants/"+f.tenant+"/bank-certificate", adminToken, nil,
		map[string]any{"bank": "c6", "cert_pem": certPEM, "key_pem": keyPEM})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if seen := f.reg.seen(); len(seen) != 1 || seen[0] != f.tenant {
		t.Fatalf("admin certificate registration tenants = %v, want [%s]", seen, f.tenant)
	}
}

// TestAdminCredentialRejectedSkipsRegistration proves a REJECTED admin write (unknown
// bank → 400) does NOT trigger the registration — the hook fires only after success.
func TestAdminCredentialRejectedSkipsRegistration(t *testing.T) {
	t.Parallel()
	f := newAdminRegFixture(t)

	rec := do(t, f.handler, http.MethodPut, "/admin/tenants/"+f.tenant+"/bank-credential", adminToken, nil,
		map[string]any{"bank": "definitely-not-a-bank", "client_id": "cid-a", "secret": "shh"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown bank, got %d (%s)", rec.Code, rec.Body.String())
	}
	if seen := f.reg.seen(); len(seen) != 0 {
		t.Fatalf("rejected admin write must not trigger registration, got %v", seen)
	}
}
