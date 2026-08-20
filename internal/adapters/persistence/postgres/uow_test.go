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
	"github.com/ia-dev-sindireceita/payment/internal/ports"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// seedTenant persists an active tenant so payments (FK-constrained) can be saved.
func seedTenant(t *testing.T, s *postgres.Store, id string) {
	t.Helper()
	tn, _ := tenant.New(id, id, time.Unix(1, 0).UTC())
	if err := s.SaveTenant(context.Background(), tn); err != nil {
		t.Fatalf("seed tenant %s: %v", id, err)
	}
}

func TestWithinTxCommitAndRollback(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "t1")
	now := time.Unix(2, 0).UTC()

	// Commit: payment + ledger persist together.
	p, _ := payment.New("p1", "t1", "pix.create", "k1", mustMoney(t), now)
	p.SetTxID("tx1")
	entry, _ := billing.NewLedgerEntry("l1", "t1", "pix.create", "p1", 120, now)
	if err := s.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.SavePayment(ctx, p); err != nil {
			return err
		}
		return r.AppendLedgerEntry(ctx, entry)
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := s.FindPaymentByID(ctx, "t1", "p1"); err != nil {
		t.Fatalf("committed payment missing: %v", err)
	}

	// Rollback: an error after a write must undo it.
	boom := errors.New("boom")
	p2, _ := payment.New("p2", "t1", "pix.create", "k2", mustMoney(t), now)
	err := s.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.SavePayment(ctx, p2); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	if _, err := s.FindPaymentByID(ctx, "t1", "p2"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rolled-back payment must be absent, got %v", err)
	}
}

func TestSavePaymentUniqueViolationMapsToConflict(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	seedTenant(t, s, "t1")
	now := time.Unix(3, 0).UTC()

	p1, _ := payment.New("p1", "t1", "pix.create", "dup", mustMoney(t), now)
	if err := s.SavePayment(ctx, p1); err != nil {
		t.Fatalf("save p1: %v", err)
	}
	// Same id is an allowed upsert.
	p1.SetTxID("tx1")
	if err := s.SavePayment(ctx, p1); err != nil {
		t.Fatalf("upsert p1: %v", err)
	}
	// Different id, same tenant+key → unique index violation → ErrConflict.
	p2, _ := payment.New("p2", "t1", "pix.create", "dup", mustMoney(t), now)
	if err := s.SavePayment(ctx, p2); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
}

func TestWithinTxBeginError(t *testing.T) {
	t.Parallel()
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
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
	called := false
	if err := s.WithinTx(context.Background(), func(ports.Repository) error {
		called = true
		return nil
	}); err == nil {
		t.Fatal("expected begin-tx error on closed db")
	}
	if called {
		t.Fatal("callback must not run when the transaction cannot begin")
	}
}
