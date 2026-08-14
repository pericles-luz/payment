package ports_test

import (
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestNormalizeBankID pins the canonicalisation + retro-compat default applied on
// the (tenantID, bankID) key path.
func TestNormalizeBankID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"", ports.BankIDC6},
		{"   ", ports.BankIDC6},
		{"c6", "c6"},
		{"C6", "c6"},
		{"  C6 ", "c6"},
		{"Itau", "itau"},
	}
	for _, tc := range cases {
		if got := ports.NormalizeBankID(tc.in); got != tc.want {
			t.Errorf("NormalizeBankID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestIsKnownBankID pins the deny-by-default allow-list: only wired banks are
// accepted; everything else (including a blank slug) is rejected.
func TestIsKnownBankID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{ports.BankIDC6, true},
		{"c6", true},
		{"itau", false},
		{"nubank", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := ports.IsKnownBankID(tc.in); got != tc.want {
			t.Errorf("IsKnownBankID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
