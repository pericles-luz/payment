package inmemory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

func money(t *testing.T) shared.Money {
	t.Helper()
	m, _ := shared.NewMoney(1000, "BRL")
	return m
}

func TestInMemoryStore(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	now := time.Unix(0, 0).UTC()

	tn, _ := tenant.New("t1", "Acme", now)
	if err := s.SaveTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindTenantByID(ctx, "t1"); err != nil {
		t.Fatalf("find tenant: %v", err)
	}
	if _, err := s.FindTenantByID(ctx, "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}

	p, _ := payment.New("p1", "t1", "pix.create", "k1", money(t), now)
	p.SetTxID("tx1")
	if err := s.SavePayment(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindPaymentByID(ctx, "t1", "p1"); err != nil {
		t.Fatalf("by id: %v", err)
	}
	if _, err := s.FindPaymentByIdempotencyKey(ctx, "t1", "k1"); err != nil {
		t.Fatalf("by idem: %v", err)
	}
	if _, err := s.FindPaymentByTxID(ctx, "t1", "tx1"); err != nil {
		t.Fatalf("by tx: %v", err)
	}
	// Cross-tenant not found.
	if _, err := s.FindPaymentByID(ctx, "t2", "p1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross by id: %v", err)
	}
	if _, err := s.FindPaymentByIdempotencyKey(ctx, "t2", "k1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross by idem: %v", err)
	}
	if _, err := s.FindPaymentByTxID(ctx, "t2", "tx1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross by tx: %v", err)
	}

	price, _ := billing.NewEndpointPricing("t1", "pix.create", 50)
	if err := s.UpsertEndpointPrice(ctx, price); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetEndpointPrice(ctx, "t1", "pix.create")
	if err != nil || got.PriceCents() != 50 {
		t.Fatalf("price: %v %v", got, err)
	}
	if _, err := s.GetEndpointPrice(ctx, "t1", "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing price: %v", err)
	}

	entry, _ := billing.NewLedgerEntry("l1", "t1", "pix.create", "p1", 50, now)
	if err := s.AppendLedgerEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}
	if s.LedgerLen() != 1 {
		t.Fatalf("ledger len: %d", s.LedgerLen())
	}

	first, _ := s.MarkProcessed(ctx, "t1", "e1")
	if !first {
		t.Fatal("first should be true")
	}
	again, _ := s.MarkProcessed(ctx, "t1", "e1")
	if again {
		t.Fatal("second should be false")
	}
}
