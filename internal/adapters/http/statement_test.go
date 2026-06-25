package http_test

import (
	"context"
	"encoding/json"
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
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// statementFixture wires a Server with the StatementService backed by the in-memory
// stub, plus two seeded/credentialed tenants (A and B) so cross-tenant isolation can
// be exercised.
type statementFixture struct {
	handler  http.Handler
	tenantID string
	bank     *bank.StubProvider
}

func stmtDate(d int) time.Time { return time.Date(2026, 6, d, 0, 0, 0, 0, time.UTC) }

func newStatementFixture(t *testing.T) *statementFixture {
	t.Helper()
	ctx := context.Background()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	bus := inmemory.NewBus()
	deps := app.Deps{
		Payments:    store,
		Tenants:     store,
		Pricing:     store,
		Ledger:      store,
		Processed:   store,
		Bus:         bus,
		Bank:        stub,
		Statement:   stub,
		Credentials: creds,
		Clock:       system.Clock{},
		IDs:         system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tnA, err := admin.CreateTenant(ctx, "Acme")
	if err != nil {
		t.Fatalf("seed tenant A: %v", err)
	}
	tnB, err := admin.CreateTenant(ctx, "Beta")
	if err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	creds.Set(tnA.ID(), ports.BankCredential{ClientID: tenantClientID, Secret: "s"})
	creds.Set(tnB.ID(), ports.BankCredential{ClientID: "c6-beta", Secret: "s"})
	// Seed entries in tenant A's account (roteiro 13.a). Tenant B has none.
	stub.SeedStatementEntries(tnA.ID(), []ports.StatementEntry{
		{ID: "e1", Date: stmtDate(5), AmountCents: 1000, Kind: "credit", Description: "in"},
		{ID: "e2", Date: stmtDate(25), AmountCents: 500, Kind: "debit", Description: "out"},
	})
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{tenantToken: tnA.ID(), tenantTokenB: tnB.ID()},
		[]string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Statement:  app.NewStatementService(deps),
		Admin:      admin,
		TenantAuth: auth,
		AdminAuth:  auth,
	})
	return &statementFixture{handler: srv.Router(), tenantID: tnA.ID(), bank: stub}
}

// roteiro 13.a: GET /v1/statement?inicio=&fim= → 200.
func TestStatementGetSuccess(t *testing.T) {
	t.Parallel()
	f := newStatementFixture(t)
	rec := do(t, f.handler, http.MethodGet, "/v1/statement?inicio=2026-06-01&fim=2026-06-10", tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var v struct {
		Entries []struct {
			ID          string `json:"id"`
			Date        string `json:"date"`
			AmountCents int64  `json:"amount_cents"`
			Kind        string `json:"kind"`
			Description string `json:"description"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Window [1,10] includes only e1.
	if len(v.Entries) != 1 || v.Entries[0].ID != "e1" {
		t.Fatalf("unexpected entries: %+v", v.Entries)
	}
	if v.Entries[0].Date != "2026-06-05" || v.Entries[0].Kind != "credit" || v.Entries[0].AmountCents != 1000 {
		t.Fatalf("view mapping: %+v", v.Entries[0])
	}

	// Deny-by-default: no token → 401.
	if rec := do(t, f.handler, http.MethodGet, "/v1/statement?inicio=2026-06-01&fim=2026-06-10", "", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without auth, got %d", rec.Code)
	}
}

// Cross-tenant isolation: tenant B (no seeded entries) sees an empty extrato even for
// the same window — the extrato is the authenticated tenant's, never selectable.
func TestStatementTenantIsolation(t *testing.T) {
	t.Parallel()
	f := newStatementFixture(t)
	rec := do(t, f.handler, http.MethodGet, "/v1/statement?inicio=2026-06-01&fim=2026-06-30", tenantTokenB, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var v struct {
		Entries []json.RawMessage `json:"entries"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if len(v.Entries) != 0 {
		t.Fatalf("tenant B must see no entries, got %d", len(v.Entries))
	}
}

// Period validation at the boundary + domain: missing/invalid dates and out-of-range
// windows are all 400.
func TestStatementPeriodErrors(t *testing.T) {
	t.Parallel()
	f := newStatementFixture(t)
	cases := []struct {
		name string
		url  string
	}{
		{"missing inicio", "/v1/statement?fim=2026-06-10"},
		{"missing fim", "/v1/statement?inicio=2026-06-01"},
		{"invalid inicio format", "/v1/statement?inicio=06-2026&fim=2026-06-10"},
		{"invalid fim format", "/v1/statement?inicio=2026-06-01&fim=notadate"},
		{"fim before inicio", "/v1/statement?inicio=2026-06-10&fim=2026-06-01"},
		{"window over 30 days", "/v1/statement?inicio=2026-06-01&fim=2026-07-15"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, f.handler, http.MethodGet, tc.url, tenantToken, nil, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
