package ports_test

import (
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestCanonicalBankID pins the strict canonicaliser shared by the HTTP per-request
// bank selector and the provider Registry key (SIN-66040 / SIN-66056). It lowercases
// and trims, and — unlike NormalizeBankID — applies NO retro-compat default: an empty
// or control-char-bearing slug is reported as not-ok so the caller fails closed.
func TestCanonicalBankID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"canonical c6", "c6", "c6", true},
		{"canonical itau", "itau", "itau", true},
		{"uppercase folded", "C6", "c6", true},
		{"surrounding space trimmed", "  c6  ", "c6", true},
		{"mixed case + space", "  ITAU ", "itau", true},
		// No retro-compat default here (that is NormalizeBankID's job): empty fails.
		{"empty", "", "", false},
		{"whitespace only", "   ", "", false},
		// Control chars are refused so a slug can never become a key fragment that
		// forges the store's tenant + "\x00" + bank composite key.
		{"nul standalone", "\x00", "", false},
		{"nul embedded", "c6\x00evil", "", false},
		{"nul prefix", "\x00c6", "", false},
		{"newline", "c6\nx", "", false},
		{"tab", "c6\tx", "", false},
		{"del 0x7f", "c6\x7fx", "", false},
		{"unit separator 0x1f", "c6\x1fx", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ports.CanonicalBankID(tc.in)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("CanonicalBankID(%q) = (%q, %v); want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestCanonicalBankIDRejectsEveryControlByte is the exhaustive complement: every byte
// below 0x20 and 0x7f embedded in an otherwise-valid slug is rejected, and every
// printable ASCII byte is accepted — the reject set is exactly the control range.
func TestCanonicalBankIDRejectsEveryControlByte(t *testing.T) {
	t.Parallel()
	for b := 0; b < 0x80; b++ {
		in := "c6" + string(rune(b)) + "x"
		_, ok := ports.CanonicalBankID(in)
		isControl := b < 0x20 || b == 0x7f
		if isControl && ok {
			t.Errorf("byte 0x%02x is a control char but slug %q was accepted", b, in)
		}
		if !isControl && !ok {
			t.Errorf("byte 0x%02x is printable but slug %q was rejected", b, in)
		}
	}
}
