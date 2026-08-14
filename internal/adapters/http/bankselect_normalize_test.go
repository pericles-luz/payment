package http

import "testing"

// TestNormalizeBankIDCharset locks the boundary charset guard that keeps a
// request-influenced bank slug from forging the secret store's composite key
// (tenantID + "\x00" + bankID, see internal/adapters/secret.credKey). The store key
// uses NUL as its field separator, so a slug carrying NUL — or any other control
// char — must be rejected BEFORE it can become a key fragment (SIN-66040, ADR-0007).
//
// This is a white-box table test (package http) on normalizeBankID itself: it proves
// every control-char class is refused at the unboundary, complementing the no-oracle
// routing matrix in bankselect_resolve_matrix_test.go.
func TestNormalizeBankIDCharset(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		// Accepted: a registered slug normalises to lowercase, trimmed.
		{"valid c6", "c6", "c6", true},
		{"valid itau", "itau", "itau", true},
		{"case-insensitive", "ITAU", "itau", true},
		{"surrounding whitespace trimmed", "  c6  ", "c6", true},
		// Rejected — empty / blank resolve to the default-selector path, never an
		// explicit slug.
		{"empty", "", "", false},
		{"whitespace only", "   ", "", false},
		// Rejected — control chars. NUL is the store-key separator; the rest are the
		// broader < 0x20 / 0x7f class the guard forbids so the charset is closed.
		{"nul standalone", "\x00", "", false},
		{"nul embedded (key-forge attempt)", "c6\x00evil", "", false},
		{"nul prefix (cross-tenant forge attempt)", "\x00c6", "", false},
		{"newline", "c6\nx", "", false},
		{"carriage return", "c6\rx", "", false},
		{"tab", "c6\tx", "", false},
		{"vertical tab", "c6\vx", "", false},
		{"form feed", "c6\fx", "", false},
		{"unit separator 0x1f", "c6\x1fx", "", false},
		{"bell 0x07", "c6\x07x", "", false},
		{"del 0x7f", "c6\x7fx", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := normalizeBankID(c.in)
			if ok != c.ok || got != c.want {
				t.Fatalf("normalizeBankID(%q) = (%q, %v); want (%q, %v)", c.in, got, ok, c.want, c.ok)
			}
		})
	}
}

// TestNormalizeBankIDRejectsEveryControlByte is an exhaustive sweep: it asserts every
// byte below 0x20 and 0x7f is rejected when embedded in an otherwise-valid slug, and
// that every printable ASCII byte in (0x20, 0x7f) is accepted. This guarantees the
// guard's reject set is exactly the control range — no gap a forged slug could slip
// through, no over-broad rejection of a legitimate printable slug.
func TestNormalizeBankIDRejectsEveryControlByte(t *testing.T) {
	for b := 0; b < 0x80; b++ {
		in := "c6" + string(rune(b)) + "x"
		_, ok := normalizeBankID(in)
		isControl := b < 0x20 || b == 0x7f
		if isControl && ok {
			t.Errorf("byte 0x%02x is a control char but slug %q was accepted", b, in)
		}
		if !isControl && !ok {
			t.Errorf("byte 0x%02x is printable but slug %q was rejected", b, in)
		}
	}
}
