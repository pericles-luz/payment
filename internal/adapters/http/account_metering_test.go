package http_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestChargeStampsAccountOnLedger is the end-to-end metering acceptance (SIN-69127):
// a charge created through the authenticated HTTP boundary lands a ledger entry
// carrying the account resolved at the auth choke-point (Principal.AccountID). The
// account is derived SERVER-SIDE from the token's tenant (self-account); the client
// never supplies it, so it cannot be spoofed. This proves the accountFromContext →
// input → ledger wiring, not just that the handler line executes.
func TestChargeStampsAccountOnLedger(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	bus := inmemory.NewBus()
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store, Processed: store,
		Bus: bus, Bank: stub, Credentials: creds, Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), "pix.create", 50); err != nil {
		t.Fatalf("seed price: %v", err)
	}
	creds.Set(tn.ID(), ports.BankCredential{ClientID: tenantClientID, Secret: "s"})
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: tn.ID()}, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges: app.NewChargeService(deps), Admin: admin, Webhooks: app.NewWebhookService(deps),
		TenantAuth: auth, AdminAuth: auth, WebhookAuth: auth,
	})
	handler := srv.Router()

	rec := do(t, handler, http.MethodPost, "/v1/charges", tenantToken,
		map[string]string{"Idempotency-Key": "k1"},
		map[string]any{"endpoint": "pix.create", "amount_cents": 2500, "currency": "BRL"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create charge = %d, body %s", rec.Code, rec.Body.String())
	}

	// The ledger entry must carry the tenant's self-account, resolved server-side.
	entries, err := store.ListLedgerEntries(context.Background(), tn.ID())
	if err != nil || len(entries) != 1 {
		t.Fatalf("ledger = %d (%v), want 1", len(entries), err)
	}
	wantAccount := account.SelfAccountID(tn.ID())
	if got := entries[0].AccountID(); got != wantAccount {
		t.Fatalf("ledger account = %q, want %q (self-account of %s)", got, wantAccount, tn.ID())
	}

	// The same entry is reachable via the account rollup read.
	byAcct, err := store.ListLedgerEntriesByAccount(context.Background(), wantAccount)
	if err != nil || len(byAcct) != 1 || byAcct[0].TenantID() != tn.ID() {
		t.Fatalf("by-account rollup = %+v (%v), want the one entry for %s", byAcct, err, tn.ID())
	}
}
