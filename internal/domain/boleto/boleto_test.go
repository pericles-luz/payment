package boleto

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// mustMoney builds a Money or fails the test.
func mustMoney(t *testing.T, cents int64, cur string) shared.Money {
	t.Helper()
	m, err := shared.NewMoney(cents, cur)
	if err != nil {
		t.Fatalf("NewMoney(%d,%q): %v", cents, cur, err)
	}
	return m
}

func dueAt(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

func TestNewValidation(t *testing.T) {
	t.Parallel()
	principal := mustMoney(t, 100000, "BRL")
	due := dueAt(t, "2026-06-10T00:00:00Z")

	cases := []struct {
		name              string
		id, tenantID      string
		principal         shared.Money
		due               time.Time
		fineBps, interest int64
		wantErr           bool
	}{
		{"happy", "b1", "t1", principal, due, 200, 100, false},
		{"happy zero rates", "b1", "t1", principal, due, 0, 0, false},
		{"empty id", "", "t1", principal, due, 200, 100, true},
		{"blank id", "   ", "t1", principal, due, 200, 100, true},
		{"empty tenant", "b1", "", principal, due, 200, 100, true},
		{"zero principal", "b1", "t1", shared.Money{}, due, 200, 100, true},
		{"zero due", "b1", "t1", principal, time.Time{}, 200, 100, true},
		{"negative fine", "b1", "t1", principal, due, -1, 100, true},
		{"fine over cap", "b1", "t1", principal, due, 201, 100, true},
		{"negative interest", "b1", "t1", principal, due, 200, -1, true},
		{"interest over cap", "b1", "t1", principal, due, 200, 101, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tc.id, tc.tenantID, tc.principal, tc.due, tc.fineBps, tc.interest)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
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

func TestAccessors(t *testing.T) {
	t.Parallel()
	principal := mustMoney(t, 100000, "BRL")
	due := dueAt(t, "2026-06-10T00:00:00Z")
	b, err := New("  b1  ", " t1 ", principal, due, 200, 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if b.ID() != "b1" || b.TenantID() != "t1" {
		t.Fatalf("identifiers not trimmed: %q/%q", b.ID(), b.TenantID())
	}
	if b.Principal().Cents() != 100000 {
		t.Fatalf("principal: %d", b.Principal().Cents())
	}
	if !b.DueDate().Equal(due) {
		t.Fatalf("due: %v", b.DueDate())
	}
	if b.FineBps() != 200 || b.MonthlyInterestBps() != 100 {
		t.Fatalf("rates: %d/%d", b.FineBps(), b.MonthlyInterestBps())
	}
}

func TestDaysLate(t *testing.T) {
	t.Parallel()
	due := dueAt(t, "2026-06-10T00:00:00Z")
	b, _ := New("b1", "t1", mustMoney(t, 100000, "BRL"), due, 200, 100)

	cases := []struct {
		name string
		at   string
		want int
	}{
		{"before due", "2026-06-01T00:00:00Z", 0},
		{"on due midnight", "2026-06-10T00:00:00Z", 0},
		{"on due late evening", "2026-06-10T23:59:59Z", 0},
		{"one day late", "2026-06-11T00:00:01Z", 1},
		{"ten days late", "2026-06-20T12:00:00Z", 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := b.DaysLate(dueAt(t, tc.at)); got != tc.want {
				t.Fatalf("DaysLate(%s) = %d, want %d", tc.at, got, tc.want)
			}
		})
	}
}

func TestFineAndInterestAndTotal(t *testing.T) {
	t.Parallel()
	due := dueAt(t, "2026-06-10T00:00:00Z")
	// principal R$1000,00; multa 2%; juros 1%/mês.
	b, _ := New("b1", "t1", mustMoney(t, 100000, "BRL"), due, 200, 100)

	// On time: no fine, no interest, total == principal.
	onTime := dueAt(t, "2026-06-10T10:00:00Z")
	if got := b.FineCents(onTime); got != 0 {
		t.Fatalf("fine on time = %d, want 0", got)
	}
	if got := b.InterestCents(onTime); got != 0 {
		t.Fatalf("interest on time = %d, want 0", got)
	}
	if got := b.AmountDueCents(onTime); got != 100000 {
		t.Fatalf("total on time = %d, want 100000", got)
	}

	// 10 days late: fine = 2000; interest = round(100000*100*10 / 300000) = 333.
	late := dueAt(t, "2026-06-20T00:00:00Z")
	if got := b.FineCents(late); got != 2000 {
		t.Fatalf("fine = %d, want 2000", got)
	}
	if got := b.InterestCents(late); got != 333 {
		t.Fatalf("interest = %d, want 333", got)
	}
	if got := b.AmountDueCents(late); got != 102333 {
		t.Fatalf("total = %d, want 102333", got)
	}
}

func TestFineRoundsHalfUp(t *testing.T) {
	t.Parallel()
	due := dueAt(t, "2026-06-10T00:00:00Z")
	// principal 12345; 2% = 246.9 -> rounds to 247.
	b, _ := New("b1", "t1", mustMoney(t, 12345, "BRL"), due, 200, 0)
	late := dueAt(t, "2026-06-11T00:00:01Z")
	if got := b.FineCents(late); got != 247 {
		t.Fatalf("fine = %d, want 247 (246.9 rounded half up)", got)
	}
}

func TestAmountDueMoney(t *testing.T) {
	t.Parallel()
	due := dueAt(t, "2026-06-10T00:00:00Z")
	b, _ := New("b1", "t1", mustMoney(t, 100000, "BRL"), due, 200, 100)
	late := dueAt(t, "2026-06-20T00:00:00Z")
	m := b.AmountDue(late)
	if m.Cents() != 102333 || m.Currency() != "BRL" {
		t.Fatalf("AmountDue = %d %s, want 102333 BRL", m.Cents(), m.Currency())
	}
	// On time it is exactly the principal money.
	if got := b.AmountDue(dueAt(t, "2026-06-10T00:00:00Z")); got.Cents() != 100000 {
		t.Fatalf("AmountDue on time = %d, want 100000", got.Cents())
	}
}
