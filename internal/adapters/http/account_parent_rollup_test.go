package http_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// seedTenantUnderAccount provisions an empresa-cliente bound to acctID (or a
// self-account when acctID is ""), seeds its "pix.create" price and a bank
// credential, and returns the tenant id. It persists the tenant with its owning
// account so the choke-point's StoreAccountResolver can read it back — the whole
// point of SIN-69222.
func seedTenantUnderAccount(t *testing.T, store *persistence.Store, creds *secret.Store, id, name, acctID string) string {
	t.Helper()
	ctx := context.Background()
	tn, err := tenant.New(id, name, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("new tenant %s: %v", id, err)
	}
	if acctID != "" {
		if err := tn.AssignAccount(acctID); err != nil {
			t.Fatalf("assign account to %s: %v", id, err)
		}
	}
	if err := store.SaveTenant(ctx, tn); err != nil {
		t.Fatalf("save tenant %s: %v", id, err)
	}
	price, err := billing.NewEndpointPricing(id, "pix.create", 50)
	if err != nil {
		t.Fatalf("build price %s: %v", id, err)
	}
	if err := store.UpsertEndpointPrice(ctx, price); err != nil {
		t.Fatalf("seed price %s: %v", id, err)
	}
	creds.Set(id, ports.BankCredential{ClientID: "c6-" + id, Secret: "s"})
	return id
}

// TestChargeStampsParentAccountOnLedger is the SIN-69222 acceptance: a charge made
// with the token of an empresa-cliente grouped under a REAL parent Account stamps
// ledger.account_id = <that Account> (NOT the derived self-account acct-<tid>), so
// "Uso por Conta" — which rolls up on ledger.account_id — sees the multi-empresa
// consumption. It also covers the retrocompat leg: a tenant with no assigned
// account still stamps its self-account, unchanged.
func TestChargeStampsParentAccountOnLedger(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	bus := inmemory.NewBus()
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store, Processed: store,
		Bus: bus, Bank: stub, Credentials: creds, Clock: system.Clock{}, IDs: system.IDProvider{},
	}

	ctx := context.Background()
	// One reseller Account X owning two empresas-clientes.
	const acctX = "acct-reseller-x"
	acc, err := account.New(acctX, "Reseller X", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("new account: %v", err)
	}
	if err := store.SaveAccount(ctx, acc); err != nil {
		t.Fatalf("save account: %v", err)
	}
	seedTenantUnderAccount(t, store, creds, "emp-one", "Empresa One", acctX)
	seedTenantUnderAccount(t, store, creds, "emp-two", "Empresa Two", acctX)
	// A legacy flat tenant with no parent account (retrocompat leg).
	seedTenantUnderAccount(t, store, creds, "emp-solo", "Empresa Solo", "")

	auth := httpadapter.NewStaticTokenAuth(map[string]string{
		"tok-one":  "emp-one",
		"tok-two":  "emp-two",
		"tok-solo": "emp-solo",
	}, nil, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:    app.NewChargeService(deps),
		Webhooks:   app.NewWebhookService(deps),
		TenantAuth: auth, AdminAuth: auth, WebhookAuth: auth,
		// The resolver under test: upgrade the choke-point's self-account default to
		// the tenant's real parent Account read from the store.
		AccountResolver: httpadapter.NewStoreAccountResolver(store),
	})
	handler := srv.Router()

	charge := func(token, idem string) {
		t.Helper()
		rec := do(t, handler, http.MethodPost, "/v1/charges", token,
			map[string]string{"Idempotency-Key": idem},
			map[string]any{"endpoint": "pix.create", "amount_cents": 2500, "currency": "BRL"})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create charge (%s) = %d, body %s", token, rec.Code, rec.Body.String())
		}
	}
	charge("tok-one", "k-one")
	charge("tok-two", "k-two")
	charge("tok-solo", "k-solo")

	// AC1: each empresa-cliente under X stamped the PARENT account, not its self-account.
	for _, tid := range []string{"emp-one", "emp-two"} {
		entries, err := store.ListLedgerEntries(ctx, tid)
		if err != nil || len(entries) != 1 {
			t.Fatalf("%s ledger = %d (%v), want 1", tid, len(entries), err)
		}
		if got := entries[0].AccountID(); got != acctX {
			t.Errorf("%s ledger account = %q, want parent %q (self-account would be %q)",
				tid, got, acctX, account.SelfAccountID(tid))
		}
	}

	// AC2: "Uso por Conta" rollup on ledger.account_id sees BOTH empresas under X.
	byAcct, err := store.ListLedgerEntriesByAccount(ctx, acctX)
	if err != nil {
		t.Fatalf("rollup by account: %v", err)
	}
	if len(byAcct) != 2 {
		t.Fatalf("rollup for %s = %d entries, want 2 (one per empresa-cliente)", acctX, len(byAcct))
	}
	seen := map[string]bool{}
	var totalCents int64
	for _, e := range byAcct {
		seen[e.TenantID()] = true
		totalCents += e.PriceCents()
	}
	if !seen["emp-one"] || !seen["emp-two"] {
		t.Errorf("rollup tenants = %v, want both emp-one and emp-two", seen)
	}
	if totalCents != 100 { // 50 + 50, AC3: rollup total = sum of the empresas.
		t.Errorf("rollup total = %d cents, want 100 (sum of the two empresas)", totalCents)
	}

	// AC (retrocompat): the flat tenant still stamps its self-account, unchanged, and
	// is NOT swept into account X's rollup.
	solo, err := store.ListLedgerEntries(ctx, "emp-solo")
	if err != nil || len(solo) != 1 {
		t.Fatalf("emp-solo ledger = %d (%v), want 1", len(solo), err)
	}
	if got, want := solo[0].AccountID(), account.SelfAccountID("emp-solo"); got != want {
		t.Errorf("emp-solo ledger account = %q, want self-account %q", got, want)
	}

	// AC4: tenant isolation intact — a token only ever writes under its own tenant id,
	// never another empresa-cliente's, even inside the same account.
	one, _ := store.ListLedgerEntries(ctx, "emp-one")
	if one[0].TenantID() != "emp-one" {
		t.Errorf("emp-one entry tenant = %q, want emp-one (isolation)", one[0].TenantID())
	}
}
