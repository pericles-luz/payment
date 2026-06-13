package consent

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func mustMoney(t *testing.T, cents int64, cur string) shared.Money {
	t.Helper()
	m, err := shared.NewMoney(cents, cur)
	if err != nil {
		t.Fatalf("NewMoney: %v", err)
	}
	return m
}

func ts(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return v
}

func TestNewValidation(t *testing.T) {
	t.Parallel()
	max := mustMoney(t, 50000, "BRL")
	start := ts(t, "2026-06-01T00:00:00Z")
	end := ts(t, "2026-12-01T00:00:00Z")

	cases := []struct {
		name       string
		id, tenant string
		taxID      string
		max        shared.Money
		freq       Frequency
		start, end time.Time
		wantErr    bool
	}{
		{"happy cpf", "c1", "t1", "12345678901", max, Monthly, start, end, false},
		{"happy cnpj", "c1", "t1", "12345678000199", max, Weekly, start, end, false},
		{"happy open ended", "c1", "t1", "12345678901", max, Yearly, start, time.Time{}, false},
		{"empty id", "", "t1", "12345678901", max, Monthly, start, end, true},
		{"empty tenant", "c1", "", "12345678901", max, Monthly, start, end, true},
		{"tax too short", "c1", "t1", "123", max, Monthly, start, end, true},
		{"tax non digit", "c1", "t1", "1234567890x", max, Monthly, start, end, true},
		{"zero max", "c1", "t1", "12345678901", shared.Money{}, Monthly, start, end, true},
		{"bad frequency", "c1", "t1", "12345678901", max, Frequency("DAILY"), start, end, true},
		{"zero start", "c1", "t1", "12345678901", max, Monthly, time.Time{}, end, true},
		{"end before start", "c1", "t1", "12345678901", max, Monthly, end, start, true},
		{"end equals start", "c1", "t1", "12345678901", max, Monthly, start, start, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tc.id, tc.tenant, tc.taxID, tc.max, tc.freq, tc.start, tc.end)
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

func TestAccessorsAndOpenEnded(t *testing.T) {
	t.Parallel()
	max := mustMoney(t, 50000, "BRL")
	start := ts(t, "2026-06-01T00:00:00Z")
	c, err := New(" c1 ", " t1 ", "12345678901", max, Monthly, start, time.Time{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.ID() != "c1" || c.TenantID() != "t1" || c.DebtorTaxID() != "12345678901" {
		t.Fatalf("accessors: %q %q %q", c.ID(), c.TenantID(), c.DebtorTaxID())
	}
	if c.MaxAmount().Cents() != 50000 || c.Frequency() != Monthly {
		t.Fatalf("max/freq: %d %s", c.MaxAmount().Cents(), c.Frequency())
	}
	if !c.Start().Equal(start) || !c.End().IsZero() {
		t.Fatalf("window: %v %v", c.Start(), c.End())
	}
	if !c.IsOpenEnded() {
		t.Fatal("expected open ended")
	}
	if c.Status() != Pending {
		t.Fatalf("status = %s, want PENDING", c.Status())
	}
}

func TestWithinWindow(t *testing.T) {
	t.Parallel()
	max := mustMoney(t, 50000, "BRL")
	start := ts(t, "2026-06-01T00:00:00Z")
	end := ts(t, "2026-12-01T00:00:00Z")
	bounded, _ := New("c1", "t1", "12345678901", max, Monthly, start, end)
	open, _ := New("c2", "t1", "12345678901", max, Monthly, start, time.Time{})

	if bounded.WithinWindow(ts(t, "2026-05-31T23:59:59Z")) {
		t.Fatal("before start should be outside window")
	}
	if !bounded.WithinWindow(start) {
		t.Fatal("start instant should be inside window")
	}
	if !bounded.WithinWindow(end) {
		t.Fatal("end instant should be inside window")
	}
	if bounded.WithinWindow(ts(t, "2026-12-01T00:00:01Z")) {
		t.Fatal("after end should be outside window")
	}
	if !open.WithinWindow(ts(t, "2030-01-01T00:00:00Z")) {
		t.Fatal("open ended should always be within window after start")
	}
	if open.WithinWindow(ts(t, "2026-05-01T00:00:00Z")) {
		t.Fatal("open ended still excludes before start")
	}
}

func TestCovers(t *testing.T) {
	t.Parallel()
	c, _ := New("c1", "t1", "12345678901", mustMoney(t, 50000, "BRL"), Monthly, ts(t, "2026-06-01T00:00:00Z"), time.Time{})
	cases := []struct {
		amount int64
		want   bool
	}{
		{0, false},
		{-1, false},
		{1, true},
		{50000, true},
		{50001, false},
	}
	for _, tc := range cases {
		if got := c.Covers(tc.amount); got != tc.want {
			t.Fatalf("Covers(%d) = %v, want %v", tc.amount, got, tc.want)
		}
	}
}

// TestCanDebit is the F1 regression: the consolidated secure-by-default debit
// guard must authorize a debit ONLY when the consent is Active AND the instant
// is inside the window AND the amount is within the ceiling — and must deny when
// any single condition fails (Pending/Cancelled, before/after window, zero/over
// the ceiling), so no caller can move recurring money by checking a subset.
func TestCanDebit(t *testing.T) {
	t.Parallel()
	max := mustMoney(t, 50000, "BRL")
	start := ts(t, "2026-06-01T00:00:00Z")
	end := ts(t, "2026-12-01T00:00:00Z")
	inWindow := ts(t, "2026-07-01T00:00:00Z")

	active := func() Consent {
		c, _ := New("c1", "t1", "12345678901", max, Monthly, start, end)
		if err := c.Activate(); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		return c
	}

	// Happy path: active, in window, within ceiling.
	if !active().CanDebit(inWindow, 50000) {
		t.Fatal("active consent inside window and ceiling must permit debit")
	}

	// Status guard: Pending and Cancelled must deny even when window/amount are fine.
	pending, _ := New("c1", "t1", "12345678901", max, Monthly, start, end)
	if pending.CanDebit(inWindow, 1) {
		t.Fatal("pending consent must deny debit")
	}
	cancelled := active()
	if err := cancelled.Cancel(); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if cancelled.CanDebit(inWindow, 1) {
		t.Fatal("cancelled consent must deny debit")
	}

	// Window guard: before start and after end must deny.
	if active().CanDebit(ts(t, "2026-05-31T23:59:59Z"), 1) {
		t.Fatal("debit before window start must be denied")
	}
	if active().CanDebit(ts(t, "2026-12-01T00:00:01Z"), 1) {
		t.Fatal("debit after window end must be denied")
	}

	// Amount guard: zero/negative and over the per-cycle ceiling must deny.
	if active().CanDebit(inWindow, 0) {
		t.Fatal("zero amount must be denied")
	}
	if active().CanDebit(inWindow, -1) {
		t.Fatal("negative amount must be denied")
	}
	if active().CanDebit(inWindow, 50001) {
		t.Fatal("amount over the per-cycle ceiling must be denied")
	}
	// Boundary: exactly at the ceiling and exactly at the window edges is allowed.
	if !active().CanDebit(start, 50000) {
		t.Fatal("debit at window start and at the ceiling must be permitted")
	}
	if !active().CanDebit(end, 1) {
		t.Fatal("debit at window end must be permitted")
	}
}

func TestLifecycleTransitions(t *testing.T) {
	t.Parallel()
	mk := func() Consent {
		c, _ := New("c1", "t1", "12345678901", mustMoney(t, 50000, "BRL"), Monthly, ts(t, "2026-06-01T00:00:00Z"), time.Time{})
		return c
	}

	// Pending -> Active.
	c := mk()
	if err := c.Activate(); err != nil {
		t.Fatalf("Activate pending: %v", err)
	}
	if c.Status() != Active {
		t.Fatalf("status = %s, want ACTIVE", c.Status())
	}
	// Active -> Activate is illegal.
	if err := c.Activate(); !errors.Is(err, shared.ErrInvalidTransition) {
		t.Fatalf("re-activate: want ErrInvalidTransition, got %v", err)
	}
	// Active -> Cancel.
	if err := c.Cancel(); err != nil {
		t.Fatalf("cancel active: %v", err)
	}
	if c.Status() != Cancelled {
		t.Fatalf("status = %s, want CANCELLED", c.Status())
	}
	// Cancelled -> Cancel is illegal.
	if err := c.Cancel(); !errors.Is(err, shared.ErrInvalidTransition) {
		t.Fatalf("re-cancel: want ErrInvalidTransition, got %v", err)
	}
	// Cancelled -> Activate is illegal.
	if err := c.Activate(); !errors.Is(err, shared.ErrInvalidTransition) {
		t.Fatalf("activate cancelled: want ErrInvalidTransition, got %v", err)
	}

	// Pending -> Cancel directly (skip activation) is legal.
	p := mk()
	if err := p.Cancel(); err != nil {
		t.Fatalf("cancel pending: %v", err)
	}
	if p.Status() != Cancelled {
		t.Fatalf("status = %s, want CANCELLED", p.Status())
	}
}
