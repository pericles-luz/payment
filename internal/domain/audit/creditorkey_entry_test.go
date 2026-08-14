package audit_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func TestNewCreditorKeySetEntry_RecordsActorBankAndAction(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	e, err := audit.NewCreditorKeySetEntry("e-1", "op-7", "ten-9", "c6", at)
	if err != nil {
		t.Fatalf("new entry: %v", err)
	}
	if e.Action() != audit.ActionSetCreditorKey {
		t.Errorf("action = %q, want %q", e.Action(), audit.ActionSetCreditorKey)
	}
	if e.OperatorID() != "op-7" {
		t.Errorf("operator = %q", e.OperatorID())
	}
	if e.TenantID() != "ten-9" {
		t.Errorf("tenant = %q", e.TenantID())
	}
	if e.BankID() != "c6" {
		t.Errorf("bank = %q", e.BankID())
	}
	if !e.At().Equal(at) {
		t.Errorf("at = %v, want %v", e.At(), at)
	}
}

func TestNewCreditorKeySetEntry_Invariants(t *testing.T) {
	t.Parallel()
	at := time.Unix(1, 0)
	cases := []struct {
		name                 string
		id, tenantID, bankID string
	}{
		{"empty id", "", "ten", "c6"},
		{"empty tenant", "e-1", "", "c6"},
		{"empty bank", "e-1", "ten", "  "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := audit.NewCreditorKeySetEntry(c.id, "op", c.tenantID, c.bankID, at); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}
}

// TestCreditorKeySetActionIsKnown asserts the new action is in the closed
// vocabulary NewEntry accepts (so it is queryable/classifiable) and the entry
// carries no key value by construction.
func TestCreditorKeySetActionIsKnown(t *testing.T) {
	t.Parallel()
	if _, err := audit.NewEntry("id", "op", audit.ActionSetCreditorKey, "ten", time.Now()); err != nil {
		t.Fatalf("ActionSetCreditorKey must be a known action: %v", err)
	}
	e, err := audit.NewCreditorKeySetEntry("id", "op", "ten", "c6", time.Now())
	if err != nil {
		t.Fatalf("new entry: %v", err)
	}
	// The entry has no field that could carry the key; render the lot and assert.
	rendered := strings.Join([]string{e.ID(), e.OperatorID(), string(e.Action()), e.TenantID(), e.BankID()}, "|")
	if strings.Contains(rendered, "@") || strings.Contains(strings.ToLower(rendered), "chave") {
		t.Fatalf("entry unexpectedly carries key-like data: %q", rendered)
	}
}
