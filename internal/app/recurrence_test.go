package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// recurrenceServiceHarness wires a RecurrenceService over the in-memory store's
// real transactional UoW (so SaveCobR + audit Append commit together) and the stub
// bank as the CobR origination port.
func recurrenceServiceHarness(t *testing.T) (*app.RecurrenceService, *harness) {
	t.Helper()
	h := newHarness(t)
	h.deps.Recs = h.store
	h.deps.CobRs = h.store
	h.deps.Audit = h.store
	h.deps.UoW = h.store
	h.deps.CobRReader = h.bank
	return app.NewRecurrenceService(h.deps), h
}

// seedMandate persists an APROVADA mandate for (tenant, idRec) in the durable store.
func seedMandate(t *testing.T, h *harness, tenant, idRec string, status recurrence.RecStatus) {
	t.Helper()
	at := time.Unix(1000, 0).UTC()
	dev, err := recurrence.NewDevedor("12345678901", "Fulano")
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
	}, at)
	if err != nil {
		t.Fatalf("new rec: %v", err)
	}
	if status != recurrence.RecCriada {
		if err := rec.Transition(status, at.Add(time.Minute)); err != nil {
			t.Fatalf("transition: %v", err)
		}
	}
	if err := h.store.SaveRec(context.Background(), rec); err != nil {
		t.Fatalf("save rec: %v", err)
	}
}

func validOriginate() app.OriginateCobRInput {
	return app.OriginateCobRInput{
		TenantID:   "t1",
		OperatorID: "op-1",
		IDRec:      "RN1",
		TxID:       "tx-1",
		Vencimento: "2026-08-01",
		ValorCents: 500,
	}
}

func TestOriginateCobRValidation(t *testing.T) {
	t.Parallel()
	svc, _ := recurrenceServiceHarness(t)
	cases := []app.OriginateCobRInput{
		{TenantID: "", IDRec: "RN1", TxID: "tx"},
		{TenantID: "t1", IDRec: "", TxID: "tx"},
		{TenantID: "t1", IDRec: "RN1", TxID: ""},
	}
	for i, c := range cases {
		if _, err := svc.OriginateCobR(context.Background(), c); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("case %d: want validation, got %v", i, err)
		}
	}
}

func TestOriginateCobRUnconfiguredFailsClosed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Recs = h.store
	h.deps.CobRs = h.store
	h.deps.Audit = h.store
	h.deps.UoW = h.store
	// CobRReader intentionally left nil.
	svc := app.NewRecurrenceService(h.deps)
	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
}

func TestOriginateCobRNoMandate(t *testing.T) {
	t.Parallel()
	svc, _ := recurrenceServiceHarness(t)
	// No mandate seeded → the gate refuses before any bank call.
	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); !errors.Is(err, recurrence.ErrMandateNotFound) {
		t.Fatalf("want ErrMandateNotFound, got %v", err)
	}
}

func TestOriginateCobRMandateNotApproved(t *testing.T) {
	t.Parallel()
	for _, st := range []recurrence.RecStatus{
		recurrence.RecCriada,
		recurrence.RecRejeitada,
		recurrence.RecExpirada,
		recurrence.RecCancelada,
	} {
		svc, h := recurrenceServiceHarness(t)
		seedMandate(t, h, "t1", "RN1", st)
		if _, err := svc.OriginateCobR(context.Background(), validOriginate()); !errors.Is(err, recurrence.ErrMandateNotApproved) {
			t.Fatalf("status %s: want ErrMandateNotApproved, got %v", st, err)
		}
		// Nothing was persisted: the refusal happened before the bank/durable write.
		if got, err := h.store.FindCobRByTxID(context.Background(), "t1", "tx-1"); err == nil {
			t.Fatalf("status %s: no charge should be persisted, got %v", st, got)
		}
		if n := len(h.store.AuditEntries()); n != 0 {
			t.Fatalf("status %s: no audit entry should be appended, got %d", st, n)
		}
	}
}

func TestOriginateCobRTenantIsolation(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	// An APROVADA mandate exists for t1; a request under t1 but the mandate keyed to
	// another tenant must not authorize. Seed for "other" and originate as "t1".
	seedMandate(t, h, "other", "RN1", recurrence.RecAprovada)
	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); !errors.Is(err, recurrence.ErrMandateNotFound) {
		t.Fatalf("cross-tenant mandate must not authorize, got %v", err)
	}
}

func TestOriginateCobRApprovedHappyPath(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	seedMandate(t, h, "t1", "RN1", recurrence.RecAprovada)

	cobr, err := svc.OriginateCobR(context.Background(), validOriginate())
	if err != nil {
		t.Fatalf("originate: %v", err)
	}
	if cobr.TxID() != "tx-1" || cobr.IDRec() != "RN1" || cobr.Status() != recurrence.CobRCriada {
		t.Fatalf("unexpected cobr: %+v", cobr)
	}
	// Persisted durably.
	got, err := h.store.FindCobRByTxID(context.Background(), "t1", "tx-1")
	if err != nil {
		t.Fatalf("charge not persisted: %v", err)
	}
	if got.ValorCents() != 500 {
		t.Fatalf("valor: %d", got.ValorCents())
	}
	// Originated at the bank (the stub recorded the charge).
	if _, err := h.bank.GetCobR(context.Background(), "t1", "tx-1"); err != nil {
		t.Fatalf("charge not originated at bank: %v", err)
	}
	// Exactly one audit entry, attributed and recording the origination of this txid.
	entries := h.store.AuditEntries()
	if len(entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Action() != audit.ActionCobRCreated || e.TxID() != "tx-1" || e.OperatorID() != "op-1" || e.TenantID() != "t1" {
		t.Fatalf("unexpected audit entry: %+v", e)
	}
}

func TestOriginateCobRIdempotentRetry(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	seedMandate(t, h, "t1", "RN1", recurrence.RecAprovada)

	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	// A retry must not double-bill or double-audit.
	if n := len(h.store.AuditEntries()); n != 1 {
		t.Fatalf("retry must not re-audit, got %d entries", n)
	}
}

// failingCobR wraps the stub and forces CreateCobR to fail, exercising the bank
// error branch (no charge persisted, no audit).
type failingCobR struct {
	ports.CobRProvider
	err error
}

func (f failingCobR) CreateCobR(context.Context, string, ports.CreateCobRRequest) (ports.CobRResult, error) {
	return ports.CobRResult{}, f.err
}

func TestOriginateCobRBankErrorPropagates(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Recs = h.store
	h.deps.CobRs = h.store
	h.deps.Audit = h.store
	h.deps.UoW = h.store
	h.deps.CobRReader = failingCobR{CobRProvider: h.bank, err: errors.New("boom")}
	svc := app.NewRecurrenceService(h.deps)
	seedMandate(t, h, "t1", "RN1", recurrence.RecAprovada)

	if _, err := svc.OriginateCobR(context.Background(), validOriginate()); err == nil {
		t.Fatal("want bank error, got nil")
	}
	// The bank failed AFTER the gate but BEFORE persistence: nothing durable changed.
	if _, err := h.store.FindCobRByTxID(context.Background(), "t1", "tx-1"); err == nil {
		t.Fatal("no charge should be persisted on bank failure")
	}
	if n := len(h.store.AuditEntries()); n != 0 {
		t.Fatalf("no audit on bank failure, got %d", n)
	}
}

// seedMandateValor persists an APROVADA mandate whose authorized value is
// valorCents, for the over-charge gate cases (seedMandate fixes it at 1000).
func seedMandateValor(t *testing.T, h *harness, tenant, idRec string, valorCents int64) {
	t.Helper()
	at := time.Unix(1000, 0).UTC()
	dev, err := recurrence.NewDevedor("12345678901", "Fulano")
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
		ValorCents:    valorCents,
	}, at)
	if err != nil {
		t.Fatalf("new rec: %v", err)
	}
	if err := rec.Transition(recurrence.RecAprovada, at.Add(time.Minute)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := h.store.SaveRec(context.Background(), rec); err != nil {
		t.Fatalf("save rec: %v", err)
	}
}

func TestOriginateCobROverChargeRefused(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	seedMandate(t, h, "t1", "RN1", recurrence.RecAprovada) // authorizes 1000
	in := validOriginate()
	in.ValorCents = 1500 // above the mandate ceiling
	if _, err := svc.OriginateCobR(context.Background(), in); !errors.Is(err, recurrence.ErrChargeExceedsMandate) {
		t.Fatalf("over-charge: want ErrChargeExceedsMandate, got %v", err)
	}
	// Refused before the bank/durable write: nothing persisted, nothing audited.
	if got, err := h.store.FindCobRByTxID(context.Background(), "t1", "tx-1"); err == nil {
		t.Fatalf("no charge should be persisted on over-charge refusal, got %v", got)
	}
	if n := len(h.store.AuditEntries()); n != 0 {
		t.Fatalf("no audit on over-charge refusal, got %d", n)
	}
}

func TestOriginateCobRAtCeilingAllowed(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	seedMandate(t, h, "t1", "RN1", recurrence.RecAprovada) // authorizes 1000
	in := validOriginate()
	in.ValorCents = 1000 // exactly the ceiling — allowed
	cobr, err := svc.OriginateCobR(context.Background(), in)
	if err != nil {
		t.Fatalf("charge at the ceiling should originate, got %v", err)
	}
	if cobr.ValorCents() != 1000 {
		t.Fatalf("valor: %d", cobr.ValorCents())
	}
}

func TestOriginateCobRVariableMandateUncapped(t *testing.T) {
	t.Parallel()
	svc, h := recurrenceServiceHarness(t)
	seedMandateValor(t, h, "t1", "RN1", 0) // variable mandate: no ceiling
	in := validOriginate()
	in.ValorCents = 999999 // any amount is allowed for a variable mandate
	if _, err := svc.OriginateCobR(context.Background(), in); err != nil {
		t.Fatalf("variable mandate must not cap the charge, got %v", err)
	}
}
