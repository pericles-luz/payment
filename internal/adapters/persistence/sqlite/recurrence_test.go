package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
	"github.com/ia-dev-sindireceita/payment/migrations"
)

func newRecStore(t *testing.T) (*sqlite.Store, string) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "rec.db")
	db, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := sqlite.Migrate(context.Background(), db, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return sqlite.NewStore(db), dsn
}

func mustDevedor(t *testing.T) recurrence.Devedor {
	t.Helper()
	d, err := recurrence.NewDevedor("12345678901", "Maria")
	if err != nil {
		t.Fatalf("devedor: %v", err)
	}
	return d
}

func mustRec(t *testing.T, idRec, tenant string) *recurrence.Rec {
	t.Helper()
	r, err := recurrence.NewRec(recurrence.NewRecParams{
		IDRec: idRec, TenantID: tenant, BankID: "c6", Contrato: "c-1",
		Devedor: mustDevedor(t), DataInicial: "2026-07-01",
		Periodicidade: recurrence.RecMensal, ValorCents: 12345,
	}, time.Date(2026, 6, 26, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewRec: %v", err)
	}
	return r
}

func mustCobR(t *testing.T, txID, idRec, tenant, venc string, cents int64) *recurrence.CobR {
	t.Helper()
	c, err := recurrence.NewCobR(recurrence.NewCobRParams{
		TxID: txID, IDRec: idRec, TenantID: tenant, Vencimento: venc, ValorCents: cents,
	}, time.Date(2026, 6, 26, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewCobR: %v", err)
	}
	return c
}

func TestSQLiteRecSaveFindAndUpsert(t *testing.T) {
	store, dsn := newRecStore(t)
	ctx := context.Background()
	r := mustRec(t, "RR1", "ten-1")
	if err := store.SaveRec(ctx, r); err != nil {
		t.Fatalf("SaveRec: %v", err)
	}

	got, err := store.FindRecByID(ctx, "ten-1", "RR1")
	if err != nil {
		t.Fatalf("FindRecByID: %v", err)
	}
	if got.Status() != recurrence.RecCriada || got.BankID() != "c6" || got.ValorCents() != 12345 {
		t.Fatalf("unexpected rehydrated rec: %+v", got)
	}
	if got.Devedor().Doc() != "12345678901" || got.Periodicidade() != recurrence.RecMensal {
		t.Fatalf("unexpected devedor/periodicidade: %+v", got)
	}

	// Upsert: a status transition is persisted by re-saving the aggregate.
	at1 := time.Date(2026, 6, 27, 9, 0, 0, 0, time.UTC)
	if err := got.Transition(recurrence.RecAprovada, at1); err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if err := store.SaveRec(ctx, got); err != nil {
		t.Fatalf("SaveRec upsert: %v", err)
	}

	// Reopen the DSN (a "restart") to prove durability of the new state.
	db2, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db2.Close() }()
	store2 := sqlite.NewStore(db2)
	reloaded, err := store2.FindRecByID(ctx, "ten-1", "RR1")
	if err != nil {
		t.Fatalf("FindRecByID after restart: %v", err)
	}
	if reloaded.Status() != recurrence.RecAprovada {
		t.Fatalf("status not durable: %q", reloaded.Status())
	}
	if !reloaded.UpdatedAt().Equal(at1) {
		t.Fatalf("updatedAt not durable: %v", reloaded.UpdatedAt())
	}
}

func TestSQLiteRecTenantScopeAndNotFound(t *testing.T) {
	store, _ := newRecStore(t)
	ctx := context.Background()
	if err := store.SaveRec(ctx, mustRec(t, "RR1", "ten-1")); err != nil {
		t.Fatalf("SaveRec: %v", err)
	}
	// Another tenant cannot read ten-1's mandate (threat P1).
	if _, err := store.FindRecByID(ctx, "ten-2", "RR1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read: want ErrNotFound, got %v", err)
	}
	if _, err := store.FindRecByID(ctx, "ten-1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing read: want ErrNotFound, got %v", err)
	}
}

func TestSQLiteCobRSaveFindList(t *testing.T) {
	store, _ := newRecStore(t)
	ctx := context.Background()
	// Two charges of the same mandate, inserted out of due-date order.
	if err := store.SaveCobR(ctx, mustCobR(t, "TX2", "RR1", "ten-1", "2026-08-10", 200)); err != nil {
		t.Fatalf("SaveCobR: %v", err)
	}
	if err := store.SaveCobR(ctx, mustCobR(t, "TX1", "RR1", "ten-1", "2026-07-10", 100)); err != nil {
		t.Fatalf("SaveCobR: %v", err)
	}
	// A charge of a different mandate and a different tenant must not leak.
	if err := store.SaveCobR(ctx, mustCobR(t, "TX3", "RR2", "ten-1", "2026-07-05", 300)); err != nil {
		t.Fatalf("SaveCobR: %v", err)
	}
	if err := store.SaveCobR(ctx, mustCobR(t, "TX9", "RR1", "ten-2", "2026-07-01", 900)); err != nil {
		t.Fatalf("SaveCobR: %v", err)
	}

	got, err := store.FindCobRByTxID(ctx, "ten-1", "TX1")
	if err != nil {
		t.Fatalf("FindCobRByTxID: %v", err)
	}
	if got.ValorCents() != 100 || got.IDRec() != "RR1" {
		t.Fatalf("unexpected cobr: %+v", got)
	}
	if _, err := store.FindCobRByTxID(ctx, "ten-2", "TX1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant cobr read: want ErrNotFound, got %v", err)
	}

	list, err := store.ListCobRByRec(ctx, "ten-1", "RR1")
	if err != nil {
		t.Fatalf("ListCobRByRec: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 charges for RR1/ten-1, got %d", len(list))
	}
	// Ordered by due date ascending.
	if list[0].TxID() != "TX1" || list[1].TxID() != "TX2" {
		t.Fatalf("unexpected order: %s, %s", list[0].TxID(), list[1].TxID())
	}
}

// TestSQLiteRecurrenceClosedDBPropagatesErrors exercises every recurrence
// method's error branch by closing the underlying database first. (A new test —
// the existing TestClosedDBPropagatesErrors covers the pre-existing methods.)
func TestSQLiteRecurrenceClosedDBPropagatesErrors(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "closed-rec.db")
	db, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := sqlite.Migrate(context.Background(), db, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := sqlite.NewStore(db)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ctx := context.Background()
	checks := []struct {
		name string
		fn   func() error
	}{
		{"SaveRec", func() error { return s.SaveRec(ctx, mustRec(t, "RR1", "ten-1")) }},
		{"FindRecByID", func() error { _, e := s.FindRecByID(ctx, "ten-1", "RR1"); return e }},
		{"SaveCobR", func() error { return s.SaveCobR(ctx, mustCobR(t, "TX1", "RR1", "ten-1", "2026-07-10", 100)) }},
		{"FindCobRByTxID", func() error { _, e := s.FindCobRByTxID(ctx, "ten-1", "TX1"); return e }},
		{"ListCobRByRec", func() error { _, e := s.ListCobRByRec(ctx, "ten-1", "RR1"); return e }},
	}
	for _, c := range checks {
		if err := c.fn(); err == nil {
			t.Errorf("%s: expected error on closed db", c.name)
		}
	}
}

// TestSQLiteFindRecByIDBadDevedorRow covers the devedor-rehydrate error branch: a
// row whose persisted devedor document is malformed cannot be reconstructed.
func TestSQLiteFindRecByIDBadDevedorRow(t *testing.T) {
	store, dsn := newRecStore(t)
	ctx := context.Background()
	// Insert a row directly with an invalid devedor_doc (too short), bypassing the
	// domain constructor so the read path must reject it.
	db, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	_, err = db.ExecContext(ctx,
		`INSERT INTO pix_rec (id_rec, tenant_id, bank_id, contrato, devedor_doc, devedor_nome,
		    data_inicial, periodicidade, valor_cents, status, created_at, updated_at)
		 VALUES ('RRbad','ten-1','c6','c-1','123','Bad','2026-07-01','MENSAL',1,'CRIADA',
		    '2026-06-26T09:00:00Z','2026-06-26T09:00:00Z')`)
	if err != nil {
		t.Fatalf("raw insert: %v", err)
	}
	if _, err := store.FindRecByID(ctx, "ten-1", "RRbad"); err == nil {
		t.Fatalf("want devedor-rehydrate error, got nil")
	}
}

// TestSQLiteRecurrenceTransitionAtomicity proves the unit-of-work seam: a Rec
// status transition and its audit entry commit together, and roll back together
// on error — closing the forensic-gap window (SIN-66025/66016 alignment).
func TestSQLiteRecurrenceTransitionAtomicity(t *testing.T) {
	store, dsn := newRecStore(t)
	ctx := context.Background()
	if err := store.SaveRec(ctx, mustRec(t, "RR1", "ten-1")); err != nil {
		t.Fatalf("seed SaveRec: %v", err)
	}

	at1 := time.Date(2026, 6, 27, 9, 0, 0, 0, time.UTC)
	wantErr := errors.New("boom after writes")

	// A transaction that approves the mandate, appends the matching audit entry,
	// then fails — both writes must roll back.
	err := store.WithinTx(ctx, func(r ports.Repository) error {
		rec, err := r.FindRecByID(ctx, "ten-1", "RR1")
		if err != nil {
			return err
		}
		if err := rec.Transition(recurrence.RecAprovada, at1); err != nil {
			return err
		}
		if err := r.SaveRec(ctx, rec); err != nil {
			return err
		}
		e, err := audit.NewRecurrenceTransitionEntry("ev-1", "op", "ten-1", "RR1", string(rec.Status()), at1)
		if err != nil {
			return err
		}
		if err := r.Append(ctx, e); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("want boom, got %v", err)
	}
	// Rolled back: still CRIADA, and no audit entry persisted.
	rolled, err := store.FindRecByID(ctx, "ten-1", "RR1")
	if err != nil {
		t.Fatalf("FindRecByID: %v", err)
	}
	if rolled.Status() != recurrence.RecCriada {
		t.Fatalf("transition not rolled back: %q", rolled.Status())
	}
	if got := readAudit(t, dsn); len(got) != 0 {
		t.Fatalf("audit entry leaked on rollback: %+v", got)
	}

	// Now commit successfully: both the new status and the audit entry persist.
	err = store.WithinTx(ctx, func(r ports.Repository) error {
		rec, err := r.FindRecByID(ctx, "ten-1", "RR1")
		if err != nil {
			return err
		}
		if err := rec.Transition(recurrence.RecAprovada, at1); err != nil {
			return err
		}
		if err := r.SaveRec(ctx, rec); err != nil {
			return err
		}
		e, err := audit.NewRecurrenceTransitionEntry("ev-2", "op", "ten-1", "RR1", string(rec.Status()), at1)
		if err != nil {
			return err
		}
		return r.Append(ctx, e)
	})
	if err != nil {
		t.Fatalf("commit tx: %v", err)
	}
	committed, err := store.FindRecByID(ctx, "ten-1", "RR1")
	if err != nil {
		t.Fatalf("FindRecByID: %v", err)
	}
	if committed.Status() != recurrence.RecAprovada {
		t.Fatalf("transition not committed: %q", committed.Status())
	}
	rows := readAudit(t, dsn)
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 audit entry after commit, got %d", len(rows))
	}
	if rows[0].action != string(audit.ActionRecApproved) || rows[0].txID != "RR1" || rows[0].tenantID != "ten-1" {
		t.Fatalf("unexpected audit row: %+v", rows[0])
	}
}
