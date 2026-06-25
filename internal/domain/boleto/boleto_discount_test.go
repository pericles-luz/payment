package boleto

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// withDiscounts builds a boleto with the given discount schedule or fails the test.
func withDiscounts(t *testing.T, principalCents int64, tiers ...DiscountTier) Boleto {
	t.Helper()
	due := dueAt(t, "2026-06-10T00:00:00Z")
	b, err := New("b1", "t1", mustMoney(t, principalCents, "BRL"), due, 0, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b, err = b.WithDiscounts(tiers...)
	if err != nil {
		t.Fatalf("WithDiscounts: %v", err)
	}
	return b
}

// roteiro 3.a: a single "até o vencimento" discount applies up to (and including) the
// due date, then disappears once the boleto is late.
func TestDiscountUntilDue(t *testing.T) {
	t.Parallel()
	b := withDiscounts(t, 100000, DiscountTier{DaysBeforeDue: 0, Bps: 1000}) // 10%

	cases := []struct {
		name string
		at   string
		want int64
	}{
		{"five days early", "2026-06-05T00:00:00Z", 10000},
		{"on due date", "2026-06-10T10:00:00Z", 10000},
		{"one day late", "2026-06-11T00:00:01Z", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := b.DiscountCents(dueAt(t, tc.at)); got != tc.want {
				t.Fatalf("DiscountCents(%s) = %d, want %d", tc.at, got, tc.want)
			}
		})
	}
	// On-time total is principal minus the discount.
	if got := b.AmountDueCents(dueAt(t, "2026-06-05T00:00:00Z")); got != 90000 {
		t.Fatalf("amount due early = %d, want 90000", got)
	}
}

// roteiro 3.a fixed variant: a fixed-cents discount applies the same way.
func TestDiscountFixedCents(t *testing.T) {
	t.Parallel()
	b := withDiscounts(t, 100000, DiscountTier{DaysBeforeDue: 0, FixedCents: 2500})
	if got := b.DiscountCents(dueAt(t, "2026-06-10T00:00:00Z")); got != 2500 {
		t.Fatalf("fixed discount = %d, want 2500", got)
	}
	if got := b.AmountDueCents(dueAt(t, "2026-06-10T00:00:00Z")); got != 97500 {
		t.Fatalf("amount due = %d, want 97500", got)
	}
}

// roteiro 3.b: an escalonado-por-dias schedule grants the most generous qualifying
// tier — more days early earns a bigger discount.
func TestDiscountTieredByDays(t *testing.T) {
	t.Parallel()
	b := withDiscounts(t, 100000,
		DiscountTier{DaysBeforeDue: 10, Bps: 1000}, // >=10 days early -> 10%
		DiscountTier{DaysBeforeDue: 5, Bps: 500},   // >=5  days early -> 5%
		DiscountTier{DaysBeforeDue: 0, Bps: 200},   // until due        -> 2%
	)
	cases := []struct {
		name string
		at   string
		want int64
	}{
		{"twelve days early -> top tier", "2026-05-29T00:00:00Z", 10000},
		{"exactly ten days early -> top tier", "2026-05-31T00:00:00Z", 10000},
		{"six days early -> mid tier", "2026-06-04T00:00:00Z", 5000},
		{"two days early -> base tier", "2026-06-08T00:00:00Z", 2000},
		{"on due -> base tier", "2026-06-10T00:00:00Z", 2000},
		{"late -> none", "2026-06-12T00:00:00Z", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := b.DiscountCents(dueAt(t, tc.at)); got != tc.want {
				t.Fatalf("DiscountCents(%s) = %d, want %d", tc.at, got, tc.want)
			}
		})
	}
}

func TestDaysEarly(t *testing.T) {
	t.Parallel()
	b := withDiscounts(t, 100000, DiscountTier{DaysBeforeDue: 0, Bps: 100})
	cases := []struct {
		at   string
		want int
	}{
		{"2026-06-01T00:00:00Z", 9},
		{"2026-06-10T00:00:00Z", 0},
		{"2026-06-11T00:00:00Z", 0}, // late => zero
	}
	for _, tc := range cases {
		if got := b.DaysEarly(dueAt(t, tc.at)); got != tc.want {
			t.Fatalf("DaysEarly(%s) = %d, want %d", tc.at, got, tc.want)
		}
	}
}

func TestNoDiscountByDefault(t *testing.T) {
	t.Parallel()
	due := dueAt(t, "2026-06-10T00:00:00Z")
	b, _ := New("b1", "t1", mustMoney(t, 100000, "BRL"), due, 0, 0)
	if got := b.DiscountCents(due); got != 0 {
		t.Fatalf("default discount = %d, want 0", got)
	}
	if got := b.Discounts(); got != nil {
		t.Fatalf("default discounts = %v, want nil", got)
	}
	// WithDiscounts with no tiers is a no-op.
	b2, err := b.WithDiscounts()
	if err != nil {
		t.Fatalf("WithDiscounts(): %v", err)
	}
	if b2.Discounts() != nil {
		t.Fatalf("empty WithDiscounts must not attach tiers")
	}
}

// roteiro 2.c: a fixed-value fine (multa valor fixo) is charged in full when late and
// is zero on time, just like the percentage form.
func TestFixedFine(t *testing.T) {
	t.Parallel()
	due := dueAt(t, "2026-06-10T00:00:00Z")
	// principal R$1000,00; fixed fine R$15,00 (within the 2% = R$20,00 ceiling).
	b, err := New("b1", "t1", mustMoney(t, 100000, "BRL"), due, 0, 100)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b, err = b.WithFixedFine(1500)
	if err != nil {
		t.Fatalf("WithFixedFine: %v", err)
	}
	if b.FineFixedCents() != 1500 {
		t.Fatalf("FineFixedCents = %d, want 1500", b.FineFixedCents())
	}
	if got := b.FineCents(dueAt(t, "2026-06-10T00:00:00Z")); got != 0 {
		t.Fatalf("fine on time = %d, want 0", got)
	}
	late := dueAt(t, "2026-06-20T00:00:00Z")
	if got := b.FineCents(late); got != 1500 {
		t.Fatalf("fixed fine = %d, want 1500", got)
	}
	// 10 days late: principal + fixed fine 1500 + interest 333.
	if got := b.AmountDueCents(late); got != 101833 {
		t.Fatalf("total = %d, want 101833", got)
	}
}

func TestFixedFineValidation(t *testing.T) {
	t.Parallel()
	due := dueAt(t, "2026-06-10T00:00:00Z")
	principal := mustMoney(t, 100000, "BRL") // 2% ceiling = 2000

	t.Run("rejects both percentage and fixed", func(t *testing.T) {
		b, _ := New("b1", "t1", principal, due, 200, 0)
		if _, err := b.WithFixedFine(1000); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
	})
	t.Run("rejects non-positive", func(t *testing.T) {
		b, _ := New("b1", "t1", principal, due, 0, 0)
		if _, err := b.WithFixedFine(0); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
	})
	t.Run("rejects over 2pct ceiling", func(t *testing.T) {
		b, _ := New("b1", "t1", principal, due, 0, 0)
		if _, err := b.WithFixedFine(2001); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
	})
	t.Run("accepts at ceiling", func(t *testing.T) {
		b, _ := New("b1", "t1", principal, due, 0, 0)
		if _, err := b.WithFixedFine(2000); err != nil {
			t.Fatalf("ceiling fixed fine should be valid: %v", err)
		}
	})
}

// roteiro 5.b: validade (data limite de pagamento) — must not precede the due date.
func TestWithValidUntil(t *testing.T) {
	t.Parallel()
	due := dueAt(t, "2026-06-10T00:00:00Z")
	b, _ := New("b1", "t1", mustMoney(t, 100000, "BRL"), due, 0, 0)

	t.Run("after due is accepted", func(t *testing.T) {
		limit := dueAt(t, "2026-06-25T00:00:00Z")
		got, err := b.WithValidUntil(limit)
		if err != nil {
			t.Fatalf("WithValidUntil: %v", err)
		}
		if !got.ValidUntil().Equal(limit) {
			t.Fatalf("ValidUntil = %v, want %v", got.ValidUntil(), limit)
		}
	})
	t.Run("equal to due is accepted", func(t *testing.T) {
		if _, err := b.WithValidUntil(due); err != nil {
			t.Fatalf("valid_until == due should be allowed: %v", err)
		}
	})
	t.Run("before due is rejected", func(t *testing.T) {
		if _, err := b.WithValidUntil(dueAt(t, "2026-06-01T00:00:00Z")); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
	})
	t.Run("zero is rejected", func(t *testing.T) {
		if _, err := b.WithValidUntil(time.Time{}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
	})
}

func TestDiscountValidation(t *testing.T) {
	t.Parallel()
	due := dueAt(t, "2026-06-10T00:00:00Z")
	base, _ := New("b1", "t1", mustMoney(t, 100000, "BRL"), due, 0, 0)

	cases := []struct {
		name  string
		tiers []DiscountTier
	}{
		{"negative days", []DiscountTier{{DaysBeforeDue: -1, Bps: 100}}},
		{"both bps and fixed", []DiscountTier{{DaysBeforeDue: 0, Bps: 100, FixedCents: 100}}},
		{"neither bps nor fixed", []DiscountTier{{DaysBeforeDue: 0}}},
		{"negative bps", []DiscountTier{{DaysBeforeDue: 0, Bps: -5}}},
		{"bps over 100pct", []DiscountTier{{DaysBeforeDue: 0, Bps: 10001}}},
		{"discount equals principal", []DiscountTier{{DaysBeforeDue: 0, FixedCents: 100000}}},
		{"discount exceeds principal", []DiscountTier{{DaysBeforeDue: 0, FixedCents: 100001}}},
		{"days not descending", []DiscountTier{
			{DaysBeforeDue: 5, Bps: 500},
			{DaysBeforeDue: 5, Bps: 200},
		}},
		{"discount not decreasing with fewer days", []DiscountTier{
			{DaysBeforeDue: 10, Bps: 200},
			{DaysBeforeDue: 5, Bps: 500},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := base.WithDiscounts(tc.tiers...); err == nil {
				t.Fatalf("want validation error for %s", tc.name)
			} else if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: want ErrValidation, got %v", tc.name, err)
			}
		})
	}
}
