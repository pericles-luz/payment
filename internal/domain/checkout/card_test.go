package checkout

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func TestParseCardType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want CardType
		ok   bool
	}{
		{"credit", CardCredit, true},
		{"debit", CardDebit, true},
		{"  CREDIT ", CardCredit, true},
		{"Debit", CardDebit, true},
		{"crypto", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, err := ParseCardType(tc.in)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Fatalf("ParseCardType(%q) = %q,%v; want %q", tc.in, got, err, tc.want)
			}
			continue
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("ParseCardType(%q): want validation error, got %v", tc.in, err)
		}
	}
}

func TestSessionWithCard(t *testing.T) {
	t.Parallel()
	item, err := NewItem("a", 1000)
	if err != nil {
		t.Fatalf("item: %v", err)
	}
	exp := time.Unix(10000, 0).UTC()
	s, err := New("s1", "t1", "BRL", []Item{item}, exp)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// default (unset) before WithCard
	if s.CardType() != "" || s.RequireAuthentication() {
		t.Fatalf("defaults not zero: %q %v", s.CardType(), s.RequireAuthentication())
	}

	withAuth, err := s.WithCard(CardCredit, true, 0)
	if err != nil {
		t.Fatalf("WithCard: %v", err)
	}
	if withAuth.CardType() != CardCredit || !withAuth.RequireAuthentication() {
		t.Fatalf("WithCard not applied: %q %v", withAuth.CardType(), withAuth.RequireAuthentication())
	}
	// value receiver: original is unchanged (immutability).
	if s.CardType() != "" {
		t.Fatalf("WithCard mutated original: %q", s.CardType())
	}

	if _, err := s.WithCard(CardType("bogus"), false, 0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("WithCard(bogus): want validation error, got %v", err)
	}
}
