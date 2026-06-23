package checkout

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func ts(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

func mustItem(t *testing.T, desc string, cents int64) Item {
	t.Helper()
	it, err := NewItem(desc, cents)
	if err != nil {
		t.Fatalf("NewItem(%q,%d): %v", desc, cents, err)
	}
	return it
}

func TestNewItemValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		desc    string
		cents   int64
		wantErr bool
	}{
		{"happy", "Plano Pro", 1000, false},
		{"trimmed", "  Plano  ", 1000, false},
		{"empty desc", "", 1000, true},
		{"blank desc", "   ", 1000, true},
		{"zero amount", "x", 0, true},
		{"negative amount", "x", -1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewItem(tc.desc, tc.cents)
			if tc.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewSessionValidation(t *testing.T) {
	t.Parallel()
	exp := ts(t, "2026-06-20T00:00:00Z")
	items := []Item{mustItem(t, "a", 1000), mustItem(t, "b", 500)}

	cases := []struct {
		name     string
		id       string
		tenant   string
		currency string
		items    []Item
		exp      time.Time
		wantErr  bool
	}{
		{"happy", "s1", "t1", "BRL", items, exp, false},
		{"empty id", "", "t1", "BRL", items, exp, true},
		{"empty tenant", "s1", "", "BRL", items, exp, true},
		{"no items", "s1", "t1", "BRL", nil, exp, true},
		{"zero expiry", "s1", "t1", "BRL", items, time.Time{}, true},
		{"bad currency", "s1", "t1", "brl", items, exp, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tc.id, tc.tenant, tc.currency, tc.items, tc.exp)
			if tc.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSessionTotalsAndAccessors(t *testing.T) {
	t.Parallel()
	exp := ts(t, "2026-06-20T00:00:00Z")
	items := []Item{mustItem(t, "a", 1000), mustItem(t, "b", 500)}
	s, err := New(" s1 ", " t1 ", "BRL", items, exp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.ID() != "s1" || s.TenantID() != "t1" {
		t.Fatalf("identifiers not trimmed: %q/%q", s.ID(), s.TenantID())
	}
	if s.TotalCents() != 1500 {
		t.Fatalf("total = %d, want 1500", s.TotalCents())
	}
	if s.Total().Cents() != 1500 || s.Currency() != "BRL" {
		t.Fatalf("total money = %d %s", s.Total().Cents(), s.Currency())
	}
	if !s.ExpiresAt().Equal(exp) {
		t.Fatalf("expiry: %v", s.ExpiresAt())
	}
	got := s.Items()
	if len(got) != 2 || got[0].Description() != "a" || got[0].AmountCents() != 1000 {
		t.Fatalf("items: %+v", got)
	}
}

// A set of individually-valid positive items whose running int64 sum wraps past
// math.MaxInt64 must be rejected with ErrValidation, not silently reduced to a
// small positive total. Three items (≤100) suffice: MaxInt64+MaxInt64 wraps to
// -2 and +5 lands on 3 — a wrong but positive value that pre-fix slipped through
// NewMoney's `<= 0` guard.
func TestNewRejectsItemSumOverflow(t *testing.T) {
	t.Parallel()
	exp := ts(t, "2026-06-20T00:00:00Z")
	items := []Item{
		mustItem(t, "a", math.MaxInt64),
		mustItem(t, "b", math.MaxInt64),
		mustItem(t, "c", 5),
	}
	_, err := New("s1", "t1", "BRL", items, exp)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for overflowing item sum, got %v", err)
	}
}

func TestSessionItemsAreCopied(t *testing.T) {
	t.Parallel()
	exp := ts(t, "2026-06-20T00:00:00Z")
	items := []Item{mustItem(t, "a", 1000)}
	s, _ := New("s1", "t1", "BRL", items, exp)

	// Mutating the caller's input slice must not change the session.
	items[0] = mustItem(t, "hacked", 99999)
	if s.Items()[0].Description() != "a" || s.TotalCents() != 1000 {
		t.Fatal("session must not share storage with caller's input slice")
	}
	// Mutating the returned slice must not change the session either.
	out := s.Items()
	out[0] = mustItem(t, "hacked", 99999)
	if s.Items()[0].Description() != "a" {
		t.Fatal("Items() must return a copy")
	}
}

func TestIsExpired(t *testing.T) {
	t.Parallel()
	exp := ts(t, "2026-06-20T00:00:00Z")
	s, _ := New("s1", "t1", "BRL", []Item{mustItem(t, "a", 1000)}, exp)

	if s.IsExpired(ts(t, "2026-06-19T23:59:59Z")) {
		t.Fatal("not expired before expiry")
	}
	if s.IsExpired(exp) {
		t.Fatal("not expired exactly at expiry")
	}
	if !s.IsExpired(ts(t, "2026-06-20T00:00:01Z")) {
		t.Fatal("expired after expiry")
	}
}
