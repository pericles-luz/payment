package audit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func TestNewRecurrenceTransitionEntry(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()

	tests := []struct {
		name       string
		status     string
		wantAction audit.Action
	}{
		{"created", "CRIADA", audit.ActionRecCreated},
		{"approved", "APROVADA", audit.ActionRecApproved},
		{"rejected", "REJEITADA", audit.ActionRecRejected},
		{"expired", "EXPIRADA", audit.ActionRecExpired},
		{"cancelled", "CANCELADA", audit.ActionRecCancelled},
		{"trims status", "  APROVADA  ", audit.ActionRecApproved},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, err := audit.NewRecurrenceTransitionEntry("  ev-1 ", " op-2 ", " ten-3 ", " RR-9 ", tc.status, at)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if e.Action() != tc.wantAction {
				t.Errorf("action = %q, want %q", e.Action(), tc.wantAction)
			}
			if e.ID() != "ev-1" || e.OperatorID() != "op-2" || e.TenantID() != "ten-3" {
				t.Errorf("fields not trimmed: %+v", e)
			}
			// The subject idRec is carried in the TxID field (reusing the durable
			// audit_log mechanism, no schema change).
			if e.TxID() != "RR-9" {
				t.Errorf("idRec subject = %q, want RR-9", e.TxID())
			}
			// A recurrence transition carries no money fields and no bank slug.
			if e.ExpectedCents() != 0 || e.ReceivedCents() != 0 || e.BankID() != "" {
				t.Errorf("unexpected non-zero money/bank fields: %+v", e)
			}
		})
	}
}

func TestNewCobROriginationEntry(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()

	e, err := audit.NewCobROriginationEntry("  ev-1 ", " op-2 ", " ten-3 ", "  tx-9  ", at)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.Action() != audit.ActionCobRCreated {
		t.Errorf("action = %q, want %q", e.Action(), audit.ActionCobRCreated)
	}
	if e.ID() != "ev-1" || e.OperatorID() != "op-2" || e.TenantID() != "ten-3" {
		t.Errorf("fields not trimmed: %+v", e)
	}
	// The subject charge txid is carried in the TxID field.
	if e.TxID() != "tx-9" {
		t.Errorf("txid subject = %q, want tx-9", e.TxID())
	}
	// A CobR origination carries no money-mismatch fields and no bank slug.
	if e.ExpectedCents() != 0 || e.ReceivedCents() != 0 || e.BankID() != "" {
		t.Errorf("unexpected non-zero money/bank fields: %+v", e)
	}
}

func TestNewCobROriginationEntryRejects(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()

	tests := []struct {
		name              string
		id, operator, ten string
		txID              string
	}{
		{"empty id", "  ", "op", "ten", "tx"},
		{"empty tenant", "ev", "op", " ", "tx"},
		{"empty txid", "ev", "op", "ten", "  "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := audit.NewCobROriginationEntry(tc.id, tc.operator, tc.ten, tc.txID, at)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

func TestNewRecurrenceTransitionEntryRejects(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()

	tests := []struct {
		name                          string
		id, operatorID, tenant, idRec string
		status                        string
	}{
		{"empty id", "", "op", "ten", "RR", "APROVADA"},
		{"empty tenant", "ev", "op", "  ", "RR", "APROVADA"},
		{"empty idRec", "ev", "op", "ten", " ", "APROVADA"},
		{"unknown status", "ev", "op", "ten", "RR", "PENDENTE"},
		{"empty status", "ev", "op", "ten", "RR", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := audit.NewRecurrenceTransitionEntry(tc.id, tc.operatorID, tc.tenant, tc.idRec, tc.status, at)
			if err == nil {
				t.Fatalf("want error, got nil")
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}
