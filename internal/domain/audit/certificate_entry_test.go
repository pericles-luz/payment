package audit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// TestNewCertificateSetEntry pins the certificate-write audit record: it carries
// the non-secret bank id and the public fingerprint (in tx_id), trims its inputs,
// and sets the certificate.set action.
func TestNewCertificateSetEntry(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	e, err := audit.NewCertificateSetEntry("  id-1 ", "  op-7 ", " ten-9 ", "  c6 ", "  ab12 ", at)
	if err != nil {
		t.Fatalf("new certificate entry: %v", err)
	}
	if e.ID() != "id-1" || e.OperatorID() != "op-7" || e.TenantID() != "ten-9" {
		t.Fatalf("fields not trimmed: %+v", e)
	}
	if e.Action() != audit.ActionSetBankCertificate {
		t.Fatalf("want action %q, got %q", audit.ActionSetBankCertificate, e.Action())
	}
	if e.BankID() != "c6" {
		t.Fatalf("want bank_id c6, got %q", e.BankID())
	}
	if e.TxID() != "ab12" {
		t.Fatalf("want fingerprint in tx_id, got %q", e.TxID())
	}
	if !e.At().Equal(at) {
		t.Fatalf("want time %v, got %v", at, e.At())
	}
	if e.ExpectedCents() != 0 || e.ReceivedCents() != 0 {
		t.Fatalf("money fields must be zero for certificate.set: %+v", e)
	}
}

// TestNewCertificateSetEntryValidation pins the construction invariants: a missing
// id, tenant, bank or fingerprint is a validation error.
func TestNewCertificateSetEntryValidation(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	cases := []struct {
		name                          string
		id, tenant, bank, fingerprint string
	}{
		{"missing id", "  ", "ten", "c6", "fp"},
		{"missing tenant", "id", "  ", "c6", "fp"},
		{"missing bank", "id", "ten", "  ", "fp"},
		{"missing fingerprint", "id", "ten", "c6", "  "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := audit.NewCertificateSetEntry(tc.id, "op", tc.tenant, tc.bank, tc.fingerprint, at)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: want ErrValidation, got %v", tc.name, err)
			}
		})
	}
}

// TestCertificateSetActionIsValid pins that the new action is in the closed
// vocabulary so NewEntry accepts it.
func TestCertificateSetActionIsValid(t *testing.T) {
	t.Parallel()
	at := time.Unix(1700000000, 0).UTC()
	if _, err := audit.NewEntry("id", "op", audit.ActionSetBankCertificate, "ten", at); err != nil {
		t.Fatalf("certificate.set must be a valid action: %v", err)
	}
}
