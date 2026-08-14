package inmemory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func invLine(t *testing.T, endpoint string, calls int, cents int64) invoice.LineItem {
	t.Helper()
	l, err := invoice.NewLineItem(endpoint, calls, cents)
	if err != nil {
		t.Fatalf("line: %v", err)
	}
	return l
}

func TestInMemoryInvoiceSaveFindListIsolation(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()

	a1, _ := invoice.New("inv-a1", "t1", "acct-t1", time.Unix(1000, 0).UTC(), time.Unix(2000, 0).UTC(),
		time.Unix(3000, 0).UTC(), []invoice.LineItem{invLine(t, "GET /x", 1, 10)})
	a2, _ := invoice.New("inv-a2", "t1", "acct-t1", time.Unix(2000, 0).UTC(), time.Unix(3000, 0).UTC(),
		time.Unix(9000, 0).UTC(), []invoice.LineItem{invLine(t, "GET /x", 2, 20)})
	b1, _ := invoice.New("inv-b1", "t2", "acct-t2", time.Unix(1000, 0).UTC(), time.Unix(2000, 0).UTC(),
		time.Unix(4000, 0).UTC(), nil)
	for _, inv := range []invoice.Invoice{a1, a2, b1} {
		if err := s.SaveInvoice(ctx, inv); err != nil {
			t.Fatalf("save %s: %v", inv.ID(), err)
		}
	}

	got, err := s.FindInvoiceByID(ctx, "t1", "inv-a2")
	if err != nil || got.TotalCents() != 20 {
		t.Fatalf("find = %+v, %v", got, err)
	}
	// Cross-tenant + unknown are not found.
	if _, err := s.FindInvoiceByID(ctx, "t1", "inv-b1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant find must 404, got %v", err)
	}
	if _, err := s.FindInvoiceByID(ctx, "t1", "ghost"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown must 404, got %v", err)
	}

	list, err := s.ListInvoices(ctx, "t1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("t1 invoices = %d, want 2 (isolation)", len(list))
	}
	if list[0].ID() != "inv-a2" || list[1].ID() != "inv-a1" {
		t.Fatalf("order = %s,%s, want newest-first", list[0].ID(), list[1].ID())
	}
	if list, err := s.ListInvoices(ctx, "none"); err != nil || len(list) != 0 {
		t.Fatalf("unknown tenant list = %d (%v), want empty", len(list), err)
	}
}
