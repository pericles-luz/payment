package audit_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// TestNewCredentialSetEntry pins the credential-write audit record: it carries the
// non-secret bank id, trims its inputs, and sets the credential.set action.
func TestNewCredentialSetEntry(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	e, err := audit.NewCredentialSetEntry("  id-1 ", "  op-7 ", " ten-9 ", "  c6 ", at)
	if err != nil {
		t.Fatalf("new credential entry: %v", err)
	}
	if e.ID() != "id-1" || e.OperatorID() != "op-7" || e.TenantID() != "ten-9" {
		t.Fatalf("fields not trimmed: %+v", e)
	}
	if e.Action() != audit.ActionSetBankCredential {
		t.Fatalf("want action %q, got %q", audit.ActionSetBankCredential, e.Action())
	}
	if e.BankID() != "c6" {
		t.Fatalf("want bank_id c6, got %q", e.BankID())
	}
	if !e.At().Equal(at) {
		t.Fatalf("want time %v, got %v", at, e.At())
	}
	// Money-movement fields stay zero-valued for an admin-plane action.
	if e.TxID() != "" || e.ExpectedCents() != 0 || e.ReceivedCents() != 0 {
		t.Fatalf("money fields must be zero for credential.set: %+v", e)
	}
}

// TestNewCredentialSetEntryValidation pins the construction invariants: a missing
// id, tenant or bank is a validation error (no unclassifiable audit record).
func TestNewCredentialSetEntryValidation(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	cases := []struct {
		name             string
		id, tenant, bank string
	}{
		{"missing id", "  ", "ten", "c6"},
		{"missing tenant", "id", "  ", "c6"},
		{"missing bank", "id", "ten", "  "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := audit.NewCredentialSetEntry(tc.id, "op", tc.tenant, tc.bank, at)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: want ErrValidation, got %v", tc.name, err)
			}
		})
	}
}

// TestCredentialEntryNeverCarriesSecret is the security assertion at the domain
// boundary: NewCredentialSetEntry has no secret/client-id parameter, so a rendered
// entry cannot leak either. (Compile-time + runtime guard.)
func TestCredentialEntryNeverCarriesSecret(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	e, err := audit.NewCredentialSetEntry("id", "op", "ten", "c6", at)
	if err != nil {
		t.Fatalf("new entry: %v", err)
	}
	rendered := strings.Join([]string{e.ID(), e.OperatorID(), string(e.Action()), e.TenantID(), e.BankID()}, "|")
	for _, leak := range []string{"secret", "client", "s3cr3t"} {
		if strings.Contains(rendered, leak) {
			t.Fatalf("entry rendered unexpected sensitive token %q: %q", leak, rendered)
		}
	}
}
