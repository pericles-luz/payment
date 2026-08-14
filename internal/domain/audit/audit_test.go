package audit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func TestNewEntryValid(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	e, err := audit.NewEntry("  id-1  ", "  op-7  ", audit.ActionSetBankCredential, "  ten-9  ", at)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	if e.ID() != "id-1" {
		t.Errorf("id not trimmed: %q", e.ID())
	}
	if e.OperatorID() != "op-7" {
		t.Errorf("operator not trimmed: %q", e.OperatorID())
	}
	if e.Action() != audit.ActionSetBankCredential {
		t.Errorf("action: %q", e.Action())
	}
	if e.TenantID() != "ten-9" {
		t.Errorf("tenant not trimmed: %q", e.TenantID())
	}
	if !e.At().Equal(at) {
		t.Errorf("at: %v", e.At())
	}
}

func TestNewEntryAllowsEmptyOperator(t *testing.T) {
	t.Parallel()
	// An internal (non-attributed) caller is valid: operator id may be empty.
	if _, err := audit.NewEntry("id-1", "", audit.ActionCreateTenant, "ten-1", time.Now()); err != nil {
		t.Fatalf("empty operator should be allowed: %v", err)
	}
}

func TestNewEntryValidation(t *testing.T) {
	t.Parallel()
	at := time.Unix(1, 0)
	cases := []struct {
		name       string
		id, tenant string
		action     audit.Action
	}{
		{"missing id", "", "ten-1", audit.ActionCreateTenant},
		{"missing tenant", "id-1", "", audit.ActionCreateTenant},
		{"unknown action", "id-1", "ten-1", audit.Action("hack")},
		{"empty action", "id-1", "ten-1", audit.Action("")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := audit.NewEntry(tc.id, "op-1", tc.action, tc.tenant, at)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestKnownActionsValid(t *testing.T) {
	t.Parallel()
	for _, a := range []audit.Action{
		audit.ActionCreateTenant, audit.ActionSetEndpointPrice, audit.ActionSetBankCredential,
		audit.ActionSuspendTenant, audit.ActionActivateTenant,
	} {
		if _, err := audit.NewEntry("id", "op", a, "ten", time.Now()); err != nil {
			t.Errorf("action %q should be valid: %v", a, err)
		}
	}
}

func TestNewSettlementMismatchEntry(t *testing.T) {
	t.Parallel()
	at := time.Unix(1000, 0).UTC()
	e, err := audit.NewSettlementMismatchEntry("  id-1  ", "system:c6-webhook", "  ten-9  ", "  tx_abc  ", 10000, 6000, at)
	if err != nil {
		t.Fatalf("NewSettlementMismatchEntry: %v", err)
	}
	if e.ID() != "id-1" {
		t.Fatalf("id not trimmed: %q", e.ID())
	}
	if e.OperatorID() != "system:c6-webhook" {
		t.Fatalf("operator: %q", e.OperatorID())
	}
	if e.Action() != audit.ActionSettlementAmountMismatch {
		t.Fatalf("action: %q", e.Action())
	}
	if e.TenantID() != "ten-9" {
		t.Fatalf("tenant not trimmed: %q", e.TenantID())
	}
	if e.TxID() != "tx_abc" {
		t.Fatalf("txid not trimmed: %q", e.TxID())
	}
	if e.ExpectedCents() != 10000 || e.ReceivedCents() != 6000 {
		t.Fatalf("amounts: expected=%d received=%d", e.ExpectedCents(), e.ReceivedCents())
	}
	if !e.At().Equal(at) {
		t.Fatalf("at: %v", e.At())
	}
}

func TestNewSettlementMismatchEntryValidation(t *testing.T) {
	t.Parallel()
	at := time.Unix(1000, 0).UTC()
	cases := []struct {
		name             string
		id, tenant, txID string
	}{
		{"empty id", "", "ten", "tx"},
		{"blank id", "   ", "ten", "tx"},
		{"empty tenant", "id", "", "tx"},
		{"empty txid", "id", "ten", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := audit.NewSettlementMismatchEntry(tc.id, "system:c6-webhook", tc.tenant, tc.txID, 1, 1, at); err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
		})
	}
}

// TestSettlementMismatchActionIsValid asserts the new action is in the
// deny-by-default vocabulary so NewEntry accepts it too (admin entries built with
// it still validate), and an unknown action is still rejected.
func TestSettlementMismatchActionIsValid(t *testing.T) {
	t.Parallel()
	if _, err := audit.NewEntry("id", "op", audit.ActionSettlementAmountMismatch, "ten", time.Now()); err != nil {
		t.Fatalf("settlement.amount_mismatch should be a valid action: %v", err)
	}
	if _, err := audit.NewEntry("id", "op", audit.Action("bogus.unknown"), "ten", time.Now()); err == nil {
		t.Fatal("unknown action must be rejected (deny-by-default)")
	}
}

// TestInvoiceGeneratedActionIsValid asserts invoice.generated (SIN-69121) is in
// the deny-by-default action vocabulary so a Fatura-generation audit entry
// validates.
func TestInvoiceGeneratedActionIsValid(t *testing.T) {
	t.Parallel()
	if _, err := audit.NewEntry("id", "op", audit.ActionInvoiceGenerated, "ten", time.Now()); err != nil {
		t.Fatalf("invoice.generated should be a valid action: %v", err)
	}
}
