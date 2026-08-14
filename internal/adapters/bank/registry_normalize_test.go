package bank_test

import (
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestRegisterRejectsNonCanonicalSlug locks the secure-by-default write boundary
// (SIN-66056): Register accepts only an already-canonical slug and refuses anything
// non-canonical — uppercase, surrounding space, empty, or a control char — with an
// error, rather than silently canonicalising it or inserting a poisoned key. The
// rejected slug must NOT leak into the registry under any form.
func TestRegisterRejectsNonCanonicalSlug(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		slug string
	}{
		{"uppercase", "C6"},
		{"mixed case", "Itau"},
		{"leading space", " c6"},
		{"trailing space", "c6 "},
		{"surrounding space", "  c6  "},
		{"empty", ""},
		{"whitespace only", "   "},
		{"nul embedded", "c6\x00evil"},
		{"nul prefix", "\x00c6"},
		{"newline", "c6\nx"},
		{"tab", "c6\tx"},
		{"del 0x7f", "c6\x7fx"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := bank.NewRegistry()
			if err := reg.Register(tc.slug, bank.ProviderSet{}); err == nil {
				t.Fatalf("Register(%q) = nil error; want rejection", tc.slug)
			}
			// The poisoned slug must not be wired under its raw form...
			if reg.Has(tc.slug) {
				t.Errorf("Has(%q) = true after rejected Register; slug leaked into registry", tc.slug)
			}
			// ...nor under its canonicalised form (e.g. "C6" must not resolve "c6").
			if canon, ok := ports.CanonicalBankID(tc.slug); ok {
				if _, found := reg.Get(canon); found {
					t.Errorf("Get(%q) found a set after rejected Register(%q); leaked via canonical form", canon, tc.slug)
				}
			}
		})
	}
}

// TestRegisterAcceptsCanonicalSlug confirms no regression: a canonical lowercase slug
// (the only form the real startup wiring ever passes — ports.BankIDC6) registers
// without error and resolves on Get/Has.
func TestRegisterAcceptsCanonicalSlug(t *testing.T) {
	t.Parallel()
	for _, slug := range []string{"c6", "itau", ports.BankIDC6} {
		reg := bank.NewRegistry()
		if err := reg.Register(slug, bank.ProviderSet{}); err != nil {
			t.Fatalf("Register(%q) = %v; want nil", slug, err)
		}
		if !reg.Has(slug) {
			t.Errorf("Has(%q) = false after successful Register", slug)
		}
		if _, ok := reg.Get(slug); !ok {
			t.Errorf("Get(%q) not found after successful Register", slug)
		}
	}
}

// TestGetHasResolveByCanonicalForm proves the read boundary is forgiving but fails
// closed: a bank wired under its canonical slug resolves when queried by a
// case/space variant (Get/Has canonicalise the lookup), while a non-canonical /
// control-char query never matches.
func TestGetHasResolveByCanonicalForm(t *testing.T) {
	t.Parallel()
	reg := bank.NewRegistry()
	if err := reg.Register("c6", bank.ProviderSet{}); err != nil {
		t.Fatalf("Register(c6) = %v; want nil", err)
	}

	resolves := []string{"c6", "C6", "  c6  ", "  C6 "}
	for _, q := range resolves {
		if !reg.Has(q) {
			t.Errorf("Has(%q) = false; want true (resolve by canonical form)", q)
		}
		if _, ok := reg.Get(q); !ok {
			t.Errorf("Get(%q) not found; want resolve by canonical form", q)
		}
	}

	failClosed := []string{"", "   ", "bb", "c6\x00", "c6\nx", "\x00c6"}
	for _, q := range failClosed {
		if reg.Has(q) {
			t.Errorf("Has(%q) = true; want false (fail closed)", q)
		}
		if _, ok := reg.Get(q); ok {
			t.Errorf("Get(%q) found; want fail closed", q)
		}
	}
}
