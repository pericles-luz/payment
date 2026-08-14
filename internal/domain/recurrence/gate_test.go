package recurrence_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
)

// mandate builds an APROVADA mandate for (tenant, idRec) used as the happy-path
// baseline; callers mutate status via Transition when they need a non-approved one.
func mandate(t *testing.T, tenant, idRec string, to recurrence.RecStatus) *recurrence.Rec {
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
	if to != recurrence.RecCriada {
		if err := rec.Transition(to, at.Add(time.Minute)); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}
	return rec
}

func TestRequireApprovedMandateApproved(t *testing.T) {
	t.Parallel()
	rec := mandate(t, "t1", "RN1", recurrence.RecAprovada)
	if err := recurrence.RequireApprovedMandate(rec, "t1", "RN1"); err != nil {
		t.Fatalf("approved mandate should pass the gate, got %v", err)
	}
}

func TestRequireApprovedMandateNil(t *testing.T) {
	t.Parallel()
	if err := recurrence.RequireApprovedMandate(nil, "t1", "RN1"); !errors.Is(err, recurrence.ErrMandateNotFound) {
		t.Fatalf("nil mandate: want ErrMandateNotFound, got %v", err)
	}
}

func TestRequireApprovedMandateNotApproved(t *testing.T) {
	t.Parallel()
	// Every non-APROVADA status must be refused: the initial CRIADA and each
	// terminal state. Without an approved mandate no charge may be originated/settled.
	for _, st := range []recurrence.RecStatus{
		recurrence.RecCriada,
		recurrence.RecRejeitada,
		recurrence.RecExpirada,
		recurrence.RecCancelada,
	} {
		rec := mandate(t, "t1", "RN1", st)
		if err := recurrence.RequireApprovedMandate(rec, "t1", "RN1"); !errors.Is(err, recurrence.ErrMandateNotApproved) {
			t.Fatalf("status %s: want ErrMandateNotApproved, got %v", st, err)
		}
	}
}

func TestRequireApprovedMandateTenantMismatch(t *testing.T) {
	t.Parallel()
	rec := mandate(t, "t1", "RN1", recurrence.RecAprovada)
	// An approved mandate that belongs to another tenant must never authorize a
	// charge claimed under a different tenant (cross-tenant IDOR defense).
	if err := recurrence.RequireApprovedMandate(rec, "t2", "RN1"); !errors.Is(err, recurrence.ErrMandateMismatch) {
		t.Fatalf("tenant mismatch: want ErrMandateMismatch, got %v", err)
	}
}

func TestRequireApprovedMandateIDRecMismatch(t *testing.T) {
	t.Parallel()
	rec := mandate(t, "t1", "RN1", recurrence.RecAprovada)
	if err := recurrence.RequireApprovedMandate(rec, "t1", "RN-other"); !errors.Is(err, recurrence.ErrMandateMismatch) {
		t.Fatalf("idRec mismatch: want ErrMandateMismatch, got %v", err)
	}
}

// mandateValor builds an APROVADA mandate whose authorized value is valorCents,
// for the over-charge gate cases (the shared `mandate` helper fixes it at 1000).
func mandateValor(t *testing.T, valorCents int64) *recurrence.Rec {
	t.Helper()
	at := time.Unix(1000, 0).UTC()
	dev, err := recurrence.NewDevedor("12345678901", "Fulano")
	if err != nil {
		t.Fatalf("devedor: %v", err)
	}
	rec, err := recurrence.NewRec(recurrence.NewRecParams{
		IDRec:         "RN1",
		TenantID:      "t1",
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
	return rec
}

func TestRequireWithinAuthorizedValueFixedMandate(t *testing.T) {
	t.Parallel()
	rec := mandateValor(t, 1000) // fixed-value mandate authorizing 1000 centavos
	// At or below the ceiling is allowed; above it is refused.
	for _, charge := range []int64{1, 999, 1000} {
		if err := recurrence.RequireWithinAuthorizedValue(rec, charge); err != nil {
			t.Fatalf("charge %d within ceiling 1000 should pass, got %v", charge, err)
		}
	}
	for _, charge := range []int64{1001, 2000} {
		if err := recurrence.RequireWithinAuthorizedValue(rec, charge); !errors.Is(err, recurrence.ErrChargeExceedsMandate) {
			t.Fatalf("charge %d above ceiling 1000: want ErrChargeExceedsMandate, got %v", charge, err)
		}
	}
}

func TestRequireWithinAuthorizedValueVariableMandate(t *testing.T) {
	t.Parallel()
	rec := mandateValor(t, 0) // variable-value mandate: no in-house ceiling
	// Any positive amount is allowed for a variable mandate — the gate is a no-op.
	for _, charge := range []int64{1, 1000, 1_000_000} {
		if err := recurrence.RequireWithinAuthorizedValue(rec, charge); err != nil {
			t.Fatalf("variable mandate must not cap charge %d, got %v", charge, err)
		}
	}
}

func TestRequireWithinAuthorizedValueNilMandate(t *testing.T) {
	t.Parallel()
	if err := recurrence.RequireWithinAuthorizedValue(nil, 100); !errors.Is(err, recurrence.ErrMandateNotFound) {
		t.Fatalf("nil mandate: want ErrMandateNotFound, got %v", err)
	}
}
