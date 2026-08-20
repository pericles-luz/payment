package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// newStore opens a fresh migrated PostgreSQL database backed by a scratch database.
func newStore(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := postgres.Migrate(context.Background(), db, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return postgres.NewStore(db)
}

func mustMoney(t *testing.T) shared.Money {
	t.Helper()
	m, err := shared.NewMoney(1500, "BRL")
	if err != nil {
		t.Fatalf("money: %v", err)
	}
	return m
}

func TestTenantRoundTrip(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	now := time.Unix(1, 0).UTC()
	tn, _ := tenant.New("t1", "Acme", now)
	if err := s.SaveTenant(ctx, tn); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.FindTenantByID(ctx, "t1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.Name() != "Acme" || !got.Active() {
		t.Fatal("tenant mismatch")
	}
	if _, err := s.FindTenantByID(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}

	// Update via upsert (deactivate).
	tn.Deactivate()
	if err := s.SaveTenant(ctx, tn); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = s.FindTenantByID(ctx, "t1")
	if got.Active() {
		t.Fatal("expected inactive after update")
	}
}

func TestPaymentRoundTripAndTenantScoping(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	now := time.Unix(2, 0).UTC()

	// Two tenants to prove isolation.
	for _, id := range []string{"t1", "t2"} {
		tn, _ := tenant.New(id, id, now)
		if err := s.SaveTenant(ctx, tn); err != nil {
			t.Fatalf("save tenant %s: %v", id, err)
		}
	}

	p, _ := payment.New("p1", "t1", "pix.create", "idem1", mustMoney(t), now)
	p.SetTxID("tx1")
	if err := s.SavePayment(ctx, p); err != nil {
		t.Fatalf("save payment: %v", err)
	}

	// Owner reads succeed.
	got, err := s.FindPaymentByID(ctx, "t1", "p1")
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if got.Amount().Cents() != 1500 || got.TxID() != "tx1" {
		t.Fatal("payment mismatch")
	}
	if _, err := s.FindPaymentByIdempotencyKey(ctx, "t1", "idem1"); err != nil {
		t.Fatalf("find by idem: %v", err)
	}
	if _, err := s.FindPaymentByTxID(ctx, "t1", "tx1"); err != nil {
		t.Fatalf("find by tx: %v", err)
	}

	// Cross-tenant access is not found (IDOR/P1).
	if _, err := s.FindPaymentByID(ctx, "t2", "p1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant by id should be not found, got %v", err)
	}
	if _, err := s.FindPaymentByIdempotencyKey(ctx, "t2", "idem1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant by idem should be not found, got %v", err)
	}
	if _, err := s.FindPaymentByTxID(ctx, "t2", "tx1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant by tx should be not found, got %v", err)
	}

	// Update via upsert (settle).
	_ = p.MarkPaid("tx1", now.Add(time.Hour))
	if err := s.SavePayment(ctx, p); err != nil {
		t.Fatalf("update payment: %v", err)
	}
	got, _ = s.FindPaymentByID(ctx, "t1", "p1")
	if got.Status() != payment.StatusPaid {
		t.Fatal("expected paid after update")
	}
}

func TestPricingAndLedgerAndProcessed(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	now := time.Unix(3, 0).UTC()
	tn, _ := tenant.New("t1", "Acme", now)
	_ = s.SaveTenant(ctx, tn)

	// Pricing upsert + read.
	price, _ := billing.NewEndpointPricing("t1", "pix.create", 80)
	if err := s.UpsertEndpointPrice(ctx, price); err != nil {
		t.Fatalf("upsert price: %v", err)
	}
	got, err := s.GetEndpointPrice(ctx, "t1", "pix.create")
	if err != nil {
		t.Fatalf("get price: %v", err)
	}
	if got.PriceCents() != 80 {
		t.Fatal("price mismatch")
	}
	// Upsert overwrites.
	price2, _ := billing.NewEndpointPricing("t1", "pix.create", 120)
	_ = s.UpsertEndpointPrice(ctx, price2)
	got, _ = s.GetEndpointPrice(ctx, "t1", "pix.create")
	if got.PriceCents() != 120 {
		t.Fatal("price not updated")
	}
	if _, err := s.GetEndpointPrice(ctx, "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}

	// Ledger append.
	entry, _ := billing.NewLedgerEntry("l1", "t1", "pix.create", "p1", 120, now)
	if err := s.AppendLedgerEntry(ctx, entry); err != nil {
		t.Fatalf("append ledger: %v", err)
	}

	// Processed events idempotency.
	first, err := s.MarkProcessed(ctx, "t1", "evt1")
	if err != nil || !first {
		t.Fatalf("first mark should be true: %v %v", first, err)
	}
	again, err := s.MarkProcessed(ctx, "t1", "evt1")
	if err != nil || again {
		t.Fatalf("second mark should be false: %v %v", again, err)
	}
	// Same key, different tenant is independent.
	otherTenant, _ := tenant.New("t2", "Other", now)
	_ = s.SaveTenant(ctx, otherTenant)
	first2, _ := s.MarkProcessed(ctx, "t2", "evt1")
	if !first2 {
		t.Fatal("different tenant should be first-time")
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	for i := 0; i < 2; i++ {
		if err := postgres.Migrate(context.Background(), db, migrations.FS); err != nil {
			t.Fatalf("migrate %d: %v", i, err)
		}
	}
}
