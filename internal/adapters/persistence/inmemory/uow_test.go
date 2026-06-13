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
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func TestWithinTxCommit(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	now := time.Unix(0, 0).UTC()
	p, _ := payment.New("p1", "t1", "pix.create", "k1", money(t), now)
	entry, _ := billing.NewLedgerEntry("l1", "t1", "pix.create", "p1", 50, now)

	err := s.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.SavePayment(ctx, p); err != nil {
			return err
		}
		return r.AppendLedgerEntry(ctx, entry)
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := s.FindPaymentByID(ctx, "t1", "p1"); err != nil {
		t.Fatalf("payment should persist after commit: %v", err)
	}
	if s.LedgerLen() != 1 {
		t.Fatalf("ledger should persist after commit: %d", s.LedgerLen())
	}
}

func TestWithinTxRollback(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	now := time.Unix(0, 0).UTC()
	p, _ := payment.New("p1", "t1", "pix.create", "k1", money(t), now)
	entry, _ := billing.NewLedgerEntry("l1", "t1", "pix.create", "p1", 50, now)
	boom := errors.New("boom")

	err := s.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.SavePayment(ctx, p); err != nil {
			return err
		}
		if err := r.AppendLedgerEntry(ctx, entry); err != nil {
			return err
		}
		return boom // force rollback after writes
	})
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	if _, err := s.FindPaymentByID(ctx, "t1", "p1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("payment must be rolled back, got %v", err)
	}
	if s.LedgerLen() != 0 {
		t.Fatalf("ledger must be rolled back, got %d", s.LedgerLen())
	}
}

// A settle mutation inside a rolled-back transaction must not leak into the store.
func TestWithinTxRollbackUndoesSettle(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	now := time.Unix(0, 0).UTC()
	p, _ := payment.New("p1", "t1", "pix.create", "k1", money(t), now)
	p.SetTxID("tx1")
	if err := s.SavePayment(ctx, p); err != nil {
		t.Fatalf("seed: %v", err)
	}
	boom := errors.New("boom")
	_ = s.WithinTx(ctx, func(r ports.Repository) error {
		loaded, err := r.FindPaymentByTxID(ctx, "t1", "tx1")
		if err != nil {
			return err
		}
		if err := loaded.MarkPaid("tx1", now); err != nil {
			return err
		}
		if err := r.SavePayment(ctx, loaded); err != nil {
			return err
		}
		return boom
	})
	got, err := s.FindPaymentByID(ctx, "t1", "p1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got.Status() != payment.StatusPending {
		t.Fatalf("settle must be rolled back, status = %s", got.Status())
	}
}

// SavePayment enforces per-tenant idempotency-key uniqueness like the SQLite
// unique index: a different id reusing a key is a conflict.
func TestSavePaymentIdempotencyUniqueness(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	now := time.Unix(0, 0).UTC()
	p1, _ := payment.New("p1", "t1", "pix.create", "dup", money(t), now)
	if err := s.SavePayment(ctx, p1); err != nil {
		t.Fatalf("save p1: %v", err)
	}
	// Same id, same key is an allowed update.
	p1.SetTxID("tx1")
	if err := s.SavePayment(ctx, p1); err != nil {
		t.Fatalf("update p1: %v", err)
	}
	// Different id, same tenant+key is a conflict.
	p2, _ := payment.New("p2", "t1", "pix.create", "dup", money(t), now)
	if err := s.SavePayment(ctx, p2); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
	// Same key under a different tenant is fine (per-tenant scope).
	p3, _ := payment.New("p3", "t2", "pix.create", "dup", money(t), now)
	if err := s.SavePayment(ctx, p3); err != nil {
		t.Fatalf("cross-tenant key reuse should be allowed: %v", err)
	}
}

// txView exposes the tenant/pricing ports too; exercise them for coverage and to
// confirm they participate in the transaction.
func TestWithinTxTenantAndPricing(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	price, _ := billing.NewEndpointPricing("t1", "pix.create", 75)
	err := s.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.UpsertEndpointPrice(ctx, price); err != nil {
			return err
		}
		got, err := r.GetEndpointPrice(ctx, "t1", "pix.create")
		if err != nil {
			return err
		}
		if got.PriceCents() != 75 {
			t.Errorf("price mismatch in tx: %d", got.PriceCents())
		}
		first, err := r.MarkProcessed(ctx, "t1", "e1")
		if err != nil || !first {
			t.Errorf("mark processed in tx: %v %v", first, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("tx: %v", err)
	}
	if _, err := s.GetEndpointPrice(ctx, "t1", "pix.create"); err != nil {
		t.Fatalf("price should persist: %v", err)
	}
}
