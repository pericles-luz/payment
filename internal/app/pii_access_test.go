package app_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/access"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const (
	piiTestDoc  = "12345678901"
	piiTestNome = "Fulano de Tal"
	piiHMACKey  = "test-service-hmac-key-0123456789"
)

// advancingClock returns a time that advances by step on each call, so the read
// duration measured across two Now() calls is deterministic and non-zero.
type advancingClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func (c *advancingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.t
	c.t = c.t.Add(c.step)
	return now
}

// piiFailRepo is a Repository whose PII-access append always fails, to exercise
// Complete Mediation: a read whose access record cannot be written must be rolled
// back. It embeds ports.Repository so every other method is inherited.
type piiFailRepo struct {
	ports.Repository
}

func (piiFailRepo) RecordPIIAccess(context.Context, access.Entry) error {
	return errors.New("boom: recorder unavailable")
}

func mustPseudo(t *testing.T) access.Pseudonymizer {
	t.Helper()
	p, err := access.NewPseudonymizer([]byte(piiHMACKey))
	if err != nil {
		t.Fatalf("NewPseudonymizer: %v", err)
	}
	return p
}

func seedRecForPII(t *testing.T, store *persistence.Store, tenant, idRec string) {
	t.Helper()
	dev, err := recurrence.NewDevedor(piiTestDoc, piiTestNome)
	if err != nil {
		t.Fatalf("devedor: %v", err)
	}
	rec, err := recurrence.NewRec(recurrence.NewRecParams{
		IDRec:         idRec,
		TenantID:      tenant,
		BankID:        "c6",
		Contrato:      "C-1",
		Devedor:       dev,
		DataInicial:   "2026-07-01",
		Periodicidade: recurrence.RecMensal,
		ValorCents:    1000,
	}, time.Unix(1000, 0).UTC())
	if err != nil {
		t.Fatalf("new rec: %v", err)
	}
	if err := store.SaveRec(context.Background(), rec); err != nil {
		t.Fatalf("save rec: %v", err)
	}
}

// TestReadRecRecordsAccess is the happy path: the mandate is returned AND exactly
// one access record is appended, with the server-derived responsible, a pseudonymous
// subject_ref (NOT the plaintext document), the object and the measured duration.
func TestReadRecRecordsAccess(t *testing.T) {
	store := persistence.NewStore()
	seedRecForPII(t, store, "tnt-1", "idrec-1")
	pseudo := mustPseudo(t)
	clk := &advancingClock{t: time.Unix(2000, 0).UTC(), step: 5 * time.Millisecond}
	svc := app.NewPIIAccessService(app.Deps{
		UoW:   store,
		Clock: clk,
		IDs:   &seqIDs{},
	}, pseudo)

	rec, err := svc.ReadRec(context.Background(), app.ReadRecInput{
		TenantID:   "tnt-1",
		IDRec:      "idrec-1",
		ClientID:   "client-abc",
		OperatorID: "op-9",
	})
	if err != nil {
		t.Fatalf("ReadRec: %v", err)
	}
	if rec == nil || rec.IDRec() != "idrec-1" {
		t.Fatalf("unexpected rec: %+v", rec)
	}

	entries := store.PIIAccessEntries()
	if len(entries) != 1 {
		t.Fatalf("want 1 access entry, got %d", len(entries))
	}
	e := entries[0]
	if e.TenantID() != "tnt-1" || e.ClientID() != "client-abc" || e.OperatorID() != "op-9" {
		t.Fatalf("responsible mismatch: %+v", e)
	}
	if e.Action() != access.ActionReadRec {
		t.Fatalf("action = %q", e.Action())
	}
	if e.Object() != "rec:idrec-1" {
		t.Fatalf("object = %q", e.Object())
	}
	if want := pseudo.Ref(piiTestDoc); e.SubjectRef() != want {
		t.Fatalf("subject_ref = %q, want %q", e.SubjectRef(), want)
	}
	if e.DurationMs() != 5 {
		t.Fatalf("duration_ms = %d, want 5", e.DurationMs())
	}
}

// TestReadRecNeverLogsPlaintextPII is the minimisation regression: the access log
// must never contain devedor_doc/devedor_nome in clear (ADR-0008 §4).
func TestReadRecNeverLogsPlaintextPII(t *testing.T) {
	store := persistence.NewStore()
	seedRecForPII(t, store, "tnt-1", "idrec-1")
	svc := app.NewPIIAccessService(app.Deps{
		UoW:   store,
		Clock: fixedClock{t: time.Unix(2000, 0).UTC()},
		IDs:   &seqIDs{},
	}, mustPseudo(t))

	if _, err := svc.ReadRec(context.Background(), app.ReadRecInput{
		TenantID: "tnt-1", IDRec: "idrec-1", ClientID: "client-abc",
	}); err != nil {
		t.Fatalf("ReadRec: %v", err)
	}
	for _, e := range store.PIIAccessEntries() {
		fields := []string{e.ID(), e.TenantID(), e.ClientID(), e.OperatorID(), e.SubjectRef(), e.Object(), string(e.Action())}
		for _, f := range fields {
			if strings.Contains(f, piiTestDoc) {
				t.Fatalf("access log leaked plaintext document in %q", f)
			}
			if strings.Contains(f, piiTestNome) {
				t.Fatalf("access log leaked plaintext name in %q", f)
			}
		}
	}
}

// TestReadRecFailsWhenAccessNotRecorded is the Complete Mediation regression: if the
// access append fails, the read fails and no PII is returned, and nothing is logged
// (the transaction rolled back).
func TestReadRecFailsWhenAccessNotRecorded(t *testing.T) {
	store := persistence.NewStore()
	seedRecForPII(t, store, "tnt-1", "idrec-1")
	uow := wrapUoW{inner: store, wrap: func(r ports.Repository) ports.Repository {
		return piiFailRepo{Repository: r}
	}}
	svc := app.NewPIIAccessService(app.Deps{
		UoW:   uow,
		Clock: fixedClock{t: time.Unix(2000, 0).UTC()},
		IDs:   &seqIDs{},
	}, mustPseudo(t))

	rec, err := svc.ReadRec(context.Background(), app.ReadRecInput{TenantID: "tnt-1", IDRec: "idrec-1"})
	if err == nil {
		t.Fatalf("expected error when access append fails")
	}
	if rec != nil {
		t.Fatalf("expected no mandate returned when access append fails, got %+v", rec)
	}
	if n := len(store.PIIAccessEntries()); n != 0 {
		t.Fatalf("access log should be empty after rollback, got %d", n)
	}
}

func TestReadRecNotFoundRecordsNothing(t *testing.T) {
	store := persistence.NewStore()
	svc := app.NewPIIAccessService(app.Deps{
		UoW:   store,
		Clock: fixedClock{t: time.Unix(2000, 0).UTC()},
		IDs:   &seqIDs{},
	}, mustPseudo(t))

	_, err := svc.ReadRec(context.Background(), app.ReadRecInput{TenantID: "tnt-1", IDRec: "missing"})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if n := len(store.PIIAccessEntries()); n != 0 {
		t.Fatalf("no PII was exposed; access log must stay empty, got %d", n)
	}
}

func TestReadRecValidation(t *testing.T) {
	store := persistence.NewStore()
	svc := app.NewPIIAccessService(app.Deps{
		UoW:   store,
		Clock: fixedClock{t: time.Unix(2000, 0).UTC()},
		IDs:   &seqIDs{},
	}, mustPseudo(t))
	for _, in := range []app.ReadRecInput{
		{TenantID: "  ", IDRec: "idrec-1"},
		{TenantID: "tnt-1", IDRec: ""},
	} {
		if _, err := svc.ReadRec(context.Background(), in); !errors.As(err, new(*shared.ValidationError)) {
			t.Fatalf("want ValidationError for %+v, got %v", in, err)
		}
	}
}

// TestRetentionPurge exercises the LGPD minimisation routine: entries older than the
// window are expired; newer ones are kept (append-safe).
func TestRetentionPurge(t *testing.T) {
	store := persistence.NewStore()
	now := time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)
	pseudo := mustPseudo(t)
	// Two entries: one well outside the window, one inside.
	old, err := access.NewEntry(access.NewEntryParams{
		ID: "old", At: now.Add(-200 * 24 * time.Hour), TenantID: "tnt-1",
		SubjectRef: pseudo.Ref(piiTestDoc), Object: "rec:a", Action: access.ActionReadRec,
	})
	if err != nil {
		t.Fatalf("old entry: %v", err)
	}
	fresh, err := access.NewEntry(access.NewEntryParams{
		ID: "fresh", At: now.Add(-1 * time.Hour), TenantID: "tnt-1",
		SubjectRef: pseudo.Ref(piiTestDoc), Object: "rec:b", Action: access.ActionReadRec,
	})
	if err != nil {
		t.Fatalf("fresh entry: %v", err)
	}
	ctx := context.Background()
	if err := store.RecordPIIAccess(ctx, old); err != nil {
		t.Fatalf("record old: %v", err)
	}
	if err := store.RecordPIIAccess(ctx, fresh); err != nil {
		t.Fatalf("record fresh: %v", err)
	}

	policy, err := access.NewRetentionPolicy(access.DefaultRetention) // 180d
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	svc := app.NewPIIAccessRetentionService(store, policy, fixedClock{t: now})
	removed, err := svc.Purge(ctx)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	remaining := store.PIIAccessEntries()
	if len(remaining) != 1 || remaining[0].ID() != "fresh" {
		t.Fatalf("unexpected remaining entries: %+v", remaining)
	}
	// Re-running immediately expires nothing new (idempotent).
	again, err := svc.Purge(ctx)
	if err != nil || again != 0 {
		t.Fatalf("second purge = %d, %v; want 0, nil", again, err)
	}
}
