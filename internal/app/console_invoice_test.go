package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newInvoiceConsole builds a ConsoleService with the invoice store + audit wired
// over a real in-memory store, so the Fatura use-cases run against the same
// append-only invariants as production.
func newInvoiceConsole() (*app.ConsoleService, *persistence.Store) {
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:    store,
		Pricing:    store,
		Ledger:     store,
		Invoices:   store,
		Audit:      store,
		CredWriter: creds,
		CredReader: creds,
		Clock:      fixedClock{t: time.Unix(9000, 0).UTC()},
		IDs:        &seqIDs{},
	})
	return svc, store
}

func aug(day int) time.Time { return time.Date(2026, 8, day, 0, 0, 0, 0, time.UTC) }

func TestGenerateInvoiceFreezesConsumption(t *testing.T) {
	t.Parallel()
	svc, store := newInvoiceConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)
	// Ledger entries stamped at Unix(idN): use ids inside [Aug window] via helper's
	// time.Unix(idN). Convert a couple of concrete times to unix seconds.
	appendLedgerAt(t, store, "t1", "POST /v1/charges", 250, aug(3))
	appendLedgerAt(t, store, "t1", "POST /v1/charges", 250, aug(4))
	appendLedgerAt(t, store, "t1", "GET /v1/charges", 10, aug(5))
	appendLedgerAt(t, store, "t1", "POST /v1/charges", 999, aug(20)) // outside window

	// Half-open [Aug 1, Aug 6): includes Aug 3/4/5, excludes Aug 20.
	rng := app.ConsumptionRange{Start: aug(1), End: aug(6)}
	inv, err := svc.GenerateInvoice(ctx, "t1", rng)
	if err != nil {
		t.Fatalf("GenerateInvoice: %v", err)
	}
	if inv.TenantID() != "t1" {
		t.Fatalf("tenant = %q", inv.TenantID())
	}
	if inv.AccountID() != "acct-t1" {
		t.Fatalf("account rollup = %q, want acct-t1 (self-account default)", inv.AccountID())
	}
	if inv.TotalCalls() != 3 || inv.TotalCents() != 510 {
		t.Fatalf("totals = %d/%d, want 3/510", inv.TotalCalls(), inv.TotalCents())
	}
	lines := inv.Lines()
	if len(lines) != 2 || lines[0].Endpoint() != "GET /v1/charges" || lines[1].Endpoint() != "POST /v1/charges" {
		t.Fatalf("lines = %+v", lines)
	}
	if lines[1].Calls() != 2 || lines[1].SubtotalCents() != 500 {
		t.Fatalf("POST line = %+v", lines[1])
	}
	// Persisted append-only and readable back, tenant-scoped.
	got, err := svc.GetInvoice(ctx, "t1", inv.ID())
	if err != nil || got.ID() != inv.ID() || got.TotalCents() != 510 {
		t.Fatalf("GetInvoice = %+v, %v", got, err)
	}
	list, err := svc.ListInvoices(ctx, "t1")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListInvoices = %d, %v", len(list), err)
	}
	// Audit trail recorded the generation.
	var found bool
	for _, e := range store.AuditEntries() {
		if e.Action() == audit.ActionInvoiceGenerated && e.TenantID() == "t1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an invoice.generated audit entry")
	}
}

// appendLedgerAt appends a billable ledger entry stamped at a concrete time so an
// invoice window can be exercised with calendar dates.
func appendLedgerAt(t *testing.T, store *persistence.Store, tenantID, endpoint string, cents int64, at time.Time) {
	t.Helper()
	e, err := billing.NewLedgerEntry("led-"+endpoint+"-"+at.Format("20060102"), tenantID, endpoint, "ref", cents, at)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	if err := store.AppendLedgerEntry(context.Background(), e); err != nil {
		t.Fatalf("append ledger: %v", err)
	}
}

func TestGenerateInvoiceZeroConsumptionIsValid(t *testing.T) {
	t.Parallel()
	svc, store := newInvoiceConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)
	inv, err := svc.GenerateInvoice(ctx, "t1", app.ConsumptionRange{Start: aug(1), End: aug(2)})
	if err != nil {
		t.Fatalf("zero-consumption invoice: %v", err)
	}
	if inv.TotalCents() != 0 || inv.TotalCalls() != 0 || len(inv.Lines()) != 0 {
		t.Fatalf("expected R$0 invoice, got %+v", inv)
	}
}

func TestGenerateInvoiceRegenerationIsAppendOnly(t *testing.T) {
	t.Parallel()
	svc, store := newInvoiceConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)
	appendLedgerAt(t, store, "t1", "POST /v1/charges", 100, aug(3))
	rng := app.ConsumptionRange{Start: aug(1), End: aug(6)}
	first, err := svc.GenerateInvoice(ctx, "t1", rng)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := svc.GenerateInvoice(ctx, "t1", rng)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.ID() == second.ID() {
		t.Fatalf("regeneration must mint a new id, not overwrite")
	}
	list, err := svc.ListInvoices(ctx, "t1")
	if err != nil || len(list) != 2 {
		t.Fatalf("expected 2 invoices append-only, got %d (%v)", len(list), err)
	}
}

func TestGenerateInvoiceRejectsUnboundedOrInverted(t *testing.T) {
	t.Parallel()
	svc, store := newInvoiceConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)
	cases := []struct {
		name string
		rng  app.ConsumptionRange
	}{
		{"no start", app.ConsumptionRange{End: aug(6)}},
		{"no end", app.ConsumptionRange{Start: aug(1)}},
		{"unbounded", app.ConsumptionRange{}},
		{"start == end", app.ConsumptionRange{Start: aug(3), End: aug(3)}},
		{"start after end", app.ConsumptionRange{Start: aug(6), End: aug(1)}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := svc.GenerateInvoice(ctx, "t1", tc.rng); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestGenerateInvoiceUnknownTenant404(t *testing.T) {
	t.Parallel()
	svc, _ := newInvoiceConsole()
	ctx := context.Background()
	if _, err := svc.GenerateInvoice(ctx, "ghost", app.ConsumptionRange{Start: aug(1), End: aug(6)}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not-found, got %v", err)
	}
	if _, err := svc.ListInvoices(ctx, "ghost"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("list unknown tenant: want not-found, got %v", err)
	}
}

func TestInvoiceTenantIsolation(t *testing.T) {
	t.Parallel()
	svc, store := newInvoiceConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)
	seedTenant(t, store, "t2", "Other", true, 100)
	appendLedgerAt(t, store, "t1", "POST /v1/charges", 100, aug(3))
	inv, err := svc.GenerateInvoice(ctx, "t1", app.ConsumptionRange{Start: aug(1), End: aug(6)})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// t2 must NOT be able to read t1's invoice (threat P1 IDOR).
	if _, err := svc.GetInvoice(ctx, "t2", inv.ID()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read must 404, got %v", err)
	}
	if list, err := svc.ListInvoices(ctx, "t2"); err != nil || len(list) != 0 {
		t.Fatalf("t2 must see no invoices, got %d (%v)", len(list), err)
	}
}

func TestInvoiceUseCasesRequireStore(t *testing.T) {
	t.Parallel()
	// A console wired WITHOUT an invoice store returns ErrInvoicesUnavailable.
	store := persistence.NewStore()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Pricing: store, Ledger: store,
		Clock: fixedClock{t: time.Unix(1, 0).UTC()}, IDs: &seqIDs{},
	})
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)
	if _, err := svc.GenerateInvoice(ctx, "t1", app.ConsumptionRange{Start: aug(1), End: aug(2)}); !errors.Is(err, app.ErrInvoicesUnavailable) {
		t.Fatalf("want ErrInvoicesUnavailable, got %v", err)
	}
	if _, err := svc.ListInvoices(ctx, "t1"); !errors.Is(err, app.ErrInvoicesUnavailable) {
		t.Fatalf("list want ErrInvoicesUnavailable, got %v", err)
	}
	if _, err := svc.GetInvoice(ctx, "t1", "x"); !errors.Is(err, app.ErrInvoicesUnavailable) {
		t.Fatalf("get want ErrInvoicesUnavailable, got %v", err)
	}
}
