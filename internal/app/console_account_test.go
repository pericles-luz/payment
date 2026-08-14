package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// appendLedgerAcct appends a ledger entry stamped with an owning account (SIN-69127),
// so the account→tenant→endpoint rollup can be exercised. It mirrors appendLedger.
func appendLedgerAcct(t *testing.T, store *persistence.Store, accountID, tenantID, endpoint string, cents int64, idN int) {
	t.Helper()
	e, err := billing.NewLedgerEntry(
		"led-"+accountID+"-"+endpoint+"-"+itoaTest(idN), tenantID, endpoint, "ref", cents,
		time.Unix(int64(idN), 0).UTC(), billing.WithAccount(accountID))
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	if err := store.AppendLedgerEntry(context.Background(), e); err != nil {
		t.Fatalf("append ledger: %v", err)
	}
}

// TestConsoleAccountConsumption is the acceptance for the account→tenant→endpoint
// metering rollup: one account owning two tenants aggregates per tenant then per
// endpoint, with account-wide grand totals, and never leaks another account's usage.
func TestConsoleAccountConsumption(t *testing.T) {
	t.Parallel()
	svc, store, _ := newConsole()
	ctx := context.Background()

	// Account acct-A owns tenants t1 and t2; acct-B owns t3 (isolation control).
	appendLedgerAcct(t, store, "acct-A", "t1", "POST /v1/charges", 250, 1)
	appendLedgerAcct(t, store, "acct-A", "t1", "POST /v1/charges", 250, 2)
	appendLedgerAcct(t, store, "acct-A", "t1", "GET /v1/charges", 10, 3)
	appendLedgerAcct(t, store, "acct-A", "t2", "POST /v1/boletos", 400, 4)
	appendLedgerAcct(t, store, "acct-B", "t3", "POST /v1/charges", 999, 5) // must not leak

	rep, err := svc.AccountConsumption(ctx, "acct-A")
	if err != nil {
		t.Fatalf("account consumption: %v", err)
	}
	if rep.AccountID != "acct-A" {
		t.Fatalf("account id = %q", rep.AccountID)
	}
	// Grand totals across the account's tenants: 4 calls / 910 cents (acct-B excluded).
	if rep.TotalCalls != 4 || rep.TotalCents != 910 {
		t.Fatalf("account totals = %d/%d, want 4/910", rep.TotalCalls, rep.TotalCents)
	}
	if len(rep.Tenants) != 2 {
		t.Fatalf("tenants = %d, want 2", len(rep.Tenants))
	}
	// Tenants ordered by id: t1 then t2.
	t1 := rep.Tenants[0]
	if t1.TenantID != "t1" || t1.TotalCalls != 3 || t1.TotalCents != 510 {
		t.Fatalf("t1 rollup = %+v", t1)
	}
	// t1's lines ordered by endpoint: GET first, then POST (2 calls, 500 cents).
	if len(t1.Lines) != 2 || t1.Lines[0].Endpoint != "GET /v1/charges" || t1.Lines[0].Calls != 1 {
		t.Fatalf("t1 lines = %+v", t1.Lines)
	}
	if t1.Lines[1].Calls != 2 || t1.Lines[1].TotalCents != 500 {
		t.Fatalf("t1 post line = %+v", t1.Lines[1])
	}
	t2 := rep.Tenants[1]
	if t2.TenantID != "t2" || t2.TotalCalls != 1 || t2.TotalCents != 400 {
		t.Fatalf("t2 rollup = %+v", t2)
	}
	if len(t2.Lines) != 1 || t2.Lines[0].Endpoint != "POST /v1/boletos" {
		t.Fatalf("t2 lines = %+v", t2.Lines)
	}

	// acct-B sees only its own single entry.
	b, err := svc.AccountConsumption(ctx, "acct-B")
	if err != nil || b.TotalCalls != 1 || b.TotalCents != 999 || len(b.Tenants) != 1 {
		t.Fatalf("acct-B rollup = %+v, %v", b, err)
	}

	// An account with no entries is a zero report, not an error.
	none, err := svc.AccountConsumption(ctx, "acct-none")
	if err != nil || none.TotalCalls != 0 || len(none.Tenants) != 0 {
		t.Fatalf("empty account rollup = %+v, %v", none, err)
	}

	// A blank account id is a validation error (deny an unscoped rollup scan).
	if _, err := svc.AccountConsumption(ctx, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank account id err = %v", err)
	}
}

// TestConsoleAccountConsumptionInRange checks the half-open [Start, End) window on the
// account rollup, mirroring the per-tenant windowed behaviour.
func TestConsoleAccountConsumptionInRange(t *testing.T) {
	t.Parallel()
	svc, store, _ := newConsole()
	ctx := context.Background()

	appendLedgerAcct(t, store, "acct-A", "t1", "POST /v1/charges", 100, 10)
	appendLedgerAcct(t, store, "acct-A", "t2", "POST /v1/charges", 100, 50)
	appendLedgerAcct(t, store, "acct-A", "t1", "GET /v1/charges", 200, 5000)

	// Half-open [0, 100): includes Unix(10) and Unix(50), excludes Unix(5000).
	rng := app.ConsumptionRange{Start: time.Unix(0, 0).UTC(), End: time.Unix(100, 0).UTC()}
	rep, err := svc.AccountConsumptionInRange(ctx, "acct-A", rng)
	if err != nil {
		t.Fatalf("account consumption in range: %v", err)
	}
	if rep.TotalCalls != 2 || rep.TotalCents != 200 {
		t.Fatalf("windowed totals = %d/%d, want 2/200", rep.TotalCalls, rep.TotalCents)
	}
	if len(rep.Tenants) != 2 {
		t.Fatalf("windowed tenants = %d, want 2 (t1 and t2, one entry each)", len(rep.Tenants))
	}

	// Zero range is unbounded — every entry counts.
	all, err := svc.AccountConsumptionInRange(ctx, "acct-A", app.ConsumptionRange{})
	if err != nil || all.TotalCalls != 3 {
		t.Fatalf("unbounded = %+v, %v", all, err)
	}
}
