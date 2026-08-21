package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

func seedInvoiceTenant(t *testing.T, s interface {
	SaveTenant(context.Context, *tenant.Tenant) error
}, id string) {
	t.Helper()
	tn, _ := tenant.New(id, "Acme "+id, time.Unix(1, 0).UTC())
	if err := s.SaveTenant(context.Background(), tn); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
}

func mustInvoice(t *testing.T, id, tenantID, accountID string, from, to time.Time, lines []invoice.LineItem) invoice.Invoice {
	t.Helper()
	inv, err := invoice.New(id, tenantID, accountID, from, to, time.Unix(5000, 0).UTC(), lines)
	if err != nil {
		t.Fatalf("build invoice: %v", err)
	}
	return inv
}

func line(t *testing.T, endpoint string, calls int, cents int64) invoice.LineItem {
	t.Helper()
	l, err := invoice.NewLineItem(endpoint, calls, cents)
	if err != nil {
		t.Fatalf("line: %v", err)
	}
	return l
}

func TestInvoiceRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	seedInvoiceTenant(t, s, "t1")

	from, to := time.Unix(1000, 0).UTC(), time.Unix(2000, 0).UTC()
	inv := mustInvoice(t, "inv-1", "t1", "acct-t1", from, to, []invoice.LineItem{
		line(t, "POST /v1/charges", 2, 500),
		line(t, "GET /v1/charges", 1, 10),
	})
	if err := s.SaveInvoice(ctx, inv); err != nil {
		t.Fatalf("save invoice: %v", err)
	}

	got, err := s.FindInvoiceByID(ctx, "t1", "inv-1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.TenantID() != "t1" || got.AccountID() != "acct-t1" {
		t.Fatalf("identity = %q/%q", got.TenantID(), got.AccountID())
	}
	if !got.PeriodStart().Equal(from) || !got.PeriodEnd().Equal(to) {
		t.Fatalf("period mismatch: %v..%v", got.PeriodStart(), got.PeriodEnd())
	}
	if got.TotalCalls() != 3 || got.TotalCents() != 510 {
		t.Fatalf("totals = %d/%d, want 3/510", got.TotalCalls(), got.TotalCents())
	}
	lines := got.Lines()
	if len(lines) != 2 || lines[0].Endpoint() != "GET /v1/charges" || lines[1].Endpoint() != "POST /v1/charges" {
		t.Fatalf("lines (should be endpoint-sorted) = %+v", lines)
	}
	if lines[1].Calls() != 2 || lines[1].SubtotalCents() != 500 {
		t.Fatalf("POST line = %+v", lines[1])
	}
}

func TestInvoiceListNewestFirstAndIsolation(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	seedInvoiceTenant(t, s, "t1")
	seedInvoiceTenant(t, s, "t2")

	older, _ := invoice.New("inv-old", "t1", "acct-t1", time.Unix(1000, 0).UTC(), time.Unix(2000, 0).UTC(),
		time.Unix(3000, 0).UTC(), []invoice.LineItem{line(t, "GET /x", 1, 10)})
	newer, _ := invoice.New("inv-new", "t1", "acct-t1", time.Unix(2000, 0).UTC(), time.Unix(3000, 0).UTC(),
		time.Unix(9000, 0).UTC(), []invoice.LineItem{line(t, "GET /x", 2, 20)})
	other, _ := invoice.New("inv-t2", "t2", "acct-t2", time.Unix(1000, 0).UTC(), time.Unix(2000, 0).UTC(),
		time.Unix(4000, 0).UTC(), nil)
	for _, inv := range []invoice.Invoice{older, newer, other} {
		if err := s.SaveInvoice(ctx, inv); err != nil {
			t.Fatalf("save %s: %v", inv.ID(), err)
		}
	}

	list, err := s.ListInvoices(ctx, "t1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("t1 invoices = %d, want 2 (isolation from t2)", len(list))
	}
	if list[0].ID() != "inv-new" || list[1].ID() != "inv-old" {
		t.Fatalf("order = %s,%s, want newest-first", list[0].ID(), list[1].ID())
	}
	// Cross-tenant read is not found (threat P1).
	if _, err := s.FindInvoiceByID(ctx, "t1", "inv-t2"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant find must 404, got %v", err)
	}
	if _, err := s.FindInvoiceByID(ctx, "t1", "ghost"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id must 404, got %v", err)
	}
}

func TestInvoiceDuplicateIDConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	seedInvoiceTenant(t, s, "t1")
	inv := mustInvoice(t, "dup", "t1", "acct-t1", time.Unix(1000, 0).UTC(), time.Unix(2000, 0).UTC(),
		[]invoice.LineItem{line(t, "GET /x", 1, 10)})
	if err := s.SaveInvoice(ctx, inv); err != nil {
		t.Fatalf("first save: %v", err)
	}
	// A second insert with the same id violates the primary key — the tx is rolled
	// back and the error propagates (exercises the insert-invoice error branch).
	if err := s.SaveInvoice(ctx, inv); err == nil {
		t.Fatalf("duplicate invoice id must fail")
	}
	// Only the first invoice survives (the failed save left nothing behind).
	if list, err := s.ListInvoices(ctx, "t1"); err != nil || len(list) != 1 {
		t.Fatalf("list = %d, %v", len(list), err)
	}
}

func TestInvoiceClosedDBPropagatesErrors(t *testing.T) {
	t.Parallel()
	db, err := postgres.Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := postgres.Migrate(context.Background(), db, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := postgres.NewStore(db)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ctx := context.Background()
	inv := mustInvoice(t, "x", "t1", "acct-t1", time.Unix(1, 0).UTC(), time.Unix(2, 0).UTC(), nil)
	if err := s.SaveInvoice(ctx, inv); err == nil {
		t.Errorf("SaveInvoice on closed db must error")
	}
	if _, err := s.FindInvoiceByID(ctx, "t1", "x"); err == nil {
		t.Errorf("FindInvoiceByID on closed db must error")
	}
	if _, err := s.ListInvoices(ctx, "t1"); err == nil {
		t.Errorf("ListInvoices on closed db must error")
	}
}

func TestInvoiceZeroLinesRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	seedInvoiceTenant(t, s, "t1")
	inv := mustInvoice(t, "inv-0", "t1", "", time.Unix(1000, 0).UTC(), time.Unix(2000, 0).UTC(), nil)
	if err := s.SaveInvoice(ctx, inv); err != nil {
		t.Fatalf("save zero invoice: %v", err)
	}
	got, err := s.FindInvoiceByID(ctx, "t1", "inv-0")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.TotalCents() != 0 || len(got.Lines()) != 0 || got.AccountID() != "" {
		t.Fatalf("zero invoice mismatch: %+v", got)
	}
	if list, err := s.ListInvoices(ctx, "t1"); err != nil || len(list) != 1 {
		t.Fatalf("list = %d, %v", len(list), err)
	}
}
