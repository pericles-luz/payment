package inmemory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

var t0 = time.Date(2026, 6, 26, 9, 0, 0, 0, time.UTC)

func devedor(t *testing.T) recurrence.Devedor {
	t.Helper()
	d, err := recurrence.NewDevedor("12345678901", "Maria")
	if err != nil {
		t.Fatalf("devedor: %v", err)
	}
	return d
}

func rec(t *testing.T, idRec, tenant string) *recurrence.Rec {
	t.Helper()
	r, err := recurrence.NewRec(recurrence.NewRecParams{
		IDRec: idRec, TenantID: tenant, BankID: "c6", Contrato: "c-1",
		Devedor: devedor(t), DataInicial: "2026-07-01",
		Periodicidade: recurrence.RecMensal, ValorCents: 12345,
	}, t0)
	if err != nil {
		t.Fatalf("NewRec: %v", err)
	}
	return r
}

func cobr(t *testing.T, txID, idRec, tenant, venc string, cents int64) *recurrence.CobR {
	t.Helper()
	c, err := recurrence.NewCobR(recurrence.NewCobRParams{
		TxID: txID, IDRec: idRec, TenantID: tenant, Vencimento: venc, ValorCents: cents,
	}, t0)
	if err != nil {
		t.Fatalf("NewCobR: %v", err)
	}
	return c
}

func TestInMemoryRecSaveFindScope(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	if err := s.SaveRec(ctx, rec(t, "RR1", "ten-1")); err != nil {
		t.Fatalf("SaveRec: %v", err)
	}
	got, err := s.FindRecByID(ctx, "ten-1", "RR1")
	if err != nil {
		t.Fatalf("FindRecByID: %v", err)
	}
	if got.Status() != recurrence.RecCriada || got.ValorCents() != 12345 {
		t.Fatalf("unexpected rec: %+v", got)
	}
	if _, err := s.FindRecByID(ctx, "ten-2", "RR1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant: want ErrNotFound, got %v", err)
	}

	// FindRecByID returns a clone: mutating it must not affect stored state.
	if err := got.Transition(recurrence.RecAprovada, t0.Add(time.Hour)); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	again, err := s.FindRecByID(ctx, "ten-1", "RR1")
	if err != nil {
		t.Fatalf("FindRecByID: %v", err)
	}
	if again.Status() != recurrence.RecCriada {
		t.Fatalf("stored rec was mutated through a returned clone: %q", again.Status())
	}
}

func TestInMemoryCobRListOrderAndScope(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	_ = s.SaveCobR(ctx, cobr(t, "TX2", "RR1", "ten-1", "2026-08-10", 200))
	_ = s.SaveCobR(ctx, cobr(t, "TX1", "RR1", "ten-1", "2026-07-10", 100))
	_ = s.SaveCobR(ctx, cobr(t, "TX3", "RR2", "ten-1", "2026-07-05", 300))
	_ = s.SaveCobR(ctx, cobr(t, "TX9", "RR1", "ten-2", "2026-07-01", 900))

	got, err := s.FindCobRByTxID(ctx, "ten-1", "TX1")
	if err != nil {
		t.Fatalf("FindCobRByTxID: %v", err)
	}
	if got.ValorCents() != 100 {
		t.Fatalf("unexpected cobr: %+v", got)
	}
	if _, err := s.FindCobRByTxID(ctx, "ten-2", "TX1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant cobr: want ErrNotFound, got %v", err)
	}

	list, err := s.ListCobRByRec(ctx, "ten-1", "RR1")
	if err != nil {
		t.Fatalf("ListCobRByRec: %v", err)
	}
	if len(list) != 2 || list[0].TxID() != "TX1" || list[1].TxID() != "TX2" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

// TestInMemoryRecurrenceUoWRollback mirrors the SQLite atomicity test on the
// in-memory store: a failed transaction rolls back both the Rec save and the
// audit append (the recurrence maps are part of the snapshot).
func TestInMemoryRecurrenceUoWRollback(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	if err := s.SaveRec(ctx, rec(t, "RR1", "ten-1")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	boom := errors.New("boom")
	err := s.WithinTx(ctx, func(r ports.Repository) error {
		got, err := r.FindRecByID(ctx, "ten-1", "RR1")
		if err != nil {
			return err
		}
		if err := got.Transition(recurrence.RecAprovada, t0.Add(time.Hour)); err != nil {
			return err
		}
		if err := r.SaveRec(ctx, got); err != nil {
			return err
		}
		e, err := audit.NewRecurrenceTransitionEntry("ev", "op", "ten-1", "RR1", string(got.Status()), t0.Add(time.Hour))
		if err != nil {
			return err
		}
		if err := r.Append(ctx, e); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	got, err := s.FindRecByID(ctx, "ten-1", "RR1")
	if err != nil {
		t.Fatalf("FindRecByID: %v", err)
	}
	if got.Status() != recurrence.RecCriada {
		t.Fatalf("rec not rolled back: %q", got.Status())
	}
	if entries := s.AuditEntries(); len(entries) != 0 {
		t.Fatalf("audit leaked on rollback: %+v", entries)
	}
}
