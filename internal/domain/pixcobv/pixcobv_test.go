package pixcobv

import (
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func brl(cents int64) shared.Money {
	m, err := shared.NewMoney(cents, "BRL")
	if err != nil {
		panic(err)
	}
	return m
}

func validParams() Params {
	return Params{
		TenantID:           "t1",
		Principal:          brl(100000),
		DueDate:            time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		ValidityDays:       5,
		FineBps:            200,
		MonthlyInterestBps: 100,
		DebtorTaxID:        "12345678901",
		DebtorName:         "Maria",
		CreditorKey:        "acme@pix.example",
	}
}

func TestNewValid(t *testing.T) {
	t.Parallel()
	c, err := New(validParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.TenantID() != "t1" || c.CreditorKey() != "acme@pix.example" {
		t.Fatalf("unexpected charge: %+v", c)
	}
	if c.Debtor().Type() != DebtorPF {
		t.Fatalf("11-digit doc should be PF, got %s", c.Debtor().Type())
	}
	if c.PayableUntil() != time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("payable-until = %v", c.PayableUntil())
	}
}

func TestDebtorPJ(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.DebtorTaxID = "12345678000199" // 14 digits => CNPJ
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Debtor().Type() != DebtorPJ {
		t.Fatalf("14-digit doc should be PJ, got %s", c.Debtor().Type())
	}
}

func TestNewValidationErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*Params)
	}{
		{"missing tenant", func(p *Params) { p.TenantID = " " }},
		{"zero principal", func(p *Params) { p.Principal = shared.Money{} }},
		{"zero due date", func(p *Params) { p.DueDate = time.Time{} }},
		{"negative validity", func(p *Params) { p.ValidityDays = -1 }},
		{"fine over cap", func(p *Params) { p.FineBps = MaxFineBps + 1 }},
		{"negative fine", func(p *Params) { p.FineBps = -1 }},
		{"interest over cap", func(p *Params) { p.MonthlyInterestBps = MaxMonthlyInterestBps + 1 }},
		{"both discount forms", func(p *Params) { p.DiscountBps = 100; p.DiscountFixedCents = 100 }},
		{"discount over 100pct", func(p *Params) { p.DiscountBps = bpsDenominator + 1 }},
		{"discount >= principal", func(p *Params) { p.DiscountFixedCents = 100000 }},
		{"bad debtor doc", func(p *Params) { p.DebtorTaxID = "123" }},
		{"missing debtor name", func(p *Params) { p.DebtorName = " " }},
		{"missing creditor key", func(p *Params) { p.CreditorKey = " " }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := validParams()
			tc.mutate(&p)
			if _, err := New(p); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: want ErrValidation, got %v", tc.name, err)
			}
		})
	}
}

// Fine charged in full on the first late day; interest accrues pro rata die.
func TestFineAndInterest(t *testing.T) {
	t.Parallel()
	c, err := New(validParams()) // principal 100000, fine 200bps, interest 100bps/mo
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	onTime := c.DueDate()
	if got := c.AmountDueCents(onTime); got != 100000 {
		t.Fatalf("on time should owe principal, got %d", got)
	}
	// 30 days late: fine = 2% = 2000; interest = 1% * 30/30 = 1% = 1000.
	late := c.DueDate().AddDate(0, 0, 30)
	if got := c.FineCents(late); got != 2000 {
		t.Fatalf("fine = %d, want 2000", got)
	}
	if got := c.InterestCents(late); got != 1000 {
		t.Fatalf("interest = %d, want 1000", got)
	}
	if got := c.AmountDueCents(late); got != 103000 {
		t.Fatalf("late total = %d, want 103000", got)
	}
}

// Early-payment discount applies up to the due date and zeroes once late.
func TestDiscount(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.DiscountBps = 1000 // 10% of 100000 = 10000
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	early := c.DueDate().AddDate(0, 0, -3)
	if got := c.DiscountCents(early); got != 10000 {
		t.Fatalf("discount = %d, want 10000", got)
	}
	if got := c.AmountDueCents(early); got != 90000 {
		t.Fatalf("discounted total = %d, want 90000", got)
	}
	// A late payment never earns a discount.
	late := c.DueDate().AddDate(0, 0, 1)
	if got := c.DiscountCents(late); got != 0 {
		t.Fatalf("late discount = %d, want 0", got)
	}
}

func TestDiscountFixed(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.DiscountFixedCents = 2500
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.DiscountCents(c.DueDate()); got != 2500 {
		t.Fatalf("fixed discount = %d, want 2500", got)
	}
}

func TestExpired(t *testing.T) {
	t.Parallel()
	c, err := New(validParams()) // validity 5 days
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	within := c.DueDate().AddDate(0, 0, 5)
	if c.Expired(within) {
		t.Fatalf("payment within validity window must not be expired")
	}
	beyond := c.DueDate().AddDate(0, 0, 6)
	if !c.Expired(beyond) {
		t.Fatalf("payment past the validity window must be expired")
	}
}

func TestAmountDueMoney(t *testing.T) {
	t.Parallel()
	c, err := New(validParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m := c.AmountDue(c.DueDate())
	if m.Cents() != 100000 || m.Currency() != "BRL" {
		t.Fatalf("amount due = %+v", m)
	}
}

// TestAccessors exercises every read accessor on Charge and Debtor so the public
// surface the adapter maps onto the PSP wire is exactly what was registered.
func TestAccessors(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.DiscountFixedCents = 2500
	p.DiscountBps = 0
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.Principal().Cents(); got != 100000 {
		t.Fatalf("Principal = %d, want 100000", got)
	}
	if got := c.ValidityDays(); got != 5 {
		t.Fatalf("ValidityDays = %d, want 5", got)
	}
	if got := c.FineBps(); got != 200 {
		t.Fatalf("FineBps = %d, want 200", got)
	}
	if got := c.MonthlyInterestBps(); got != 100 {
		t.Fatalf("MonthlyInterestBps = %d, want 100", got)
	}
	if got := c.DiscountFixedCents(); got != 2500 {
		t.Fatalf("DiscountFixedCents = %d, want 2500", got)
	}
	if got := c.DiscountBps(); got != 0 {
		t.Fatalf("DiscountBps = %d, want 0", got)
	}
	d := c.Debtor()
	if d.TaxID() != "12345678901" || d.Name() != "Maria" {
		t.Fatalf("debtor = %q/%q", d.TaxID(), d.Name())
	}
}

// TestDiscountBpsAccessor covers the percentage-discount accessor on a charge that
// carries a bps discount (the fixed-discount case is covered in TestAccessors).
func TestDiscountBpsAccessor(t *testing.T) {
	t.Parallel()
	p := validParams()
	p.DiscountBps = 1000
	c, err := New(p)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.DiscountBps(); got != 1000 {
		t.Fatalf("DiscountBps = %d, want 1000", got)
	}
	if got := c.DiscountFixedCents(); got != 0 {
		t.Fatalf("DiscountFixedCents = %d, want 0", got)
	}
}

// TestDaysEarly checks the early-day count: positive before the due date, zero on
// or after it (the discount window depends on it).
func TestDaysEarly(t *testing.T) {
	t.Parallel()
	c, err := New(validParams())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.DaysEarly(c.DueDate().AddDate(0, 0, -4)); got != 4 {
		t.Fatalf("DaysEarly(4 before) = %d, want 4", got)
	}
	if got := c.DaysEarly(c.DueDate()); got != 0 {
		t.Fatalf("DaysEarly(on due) = %d, want 0", got)
	}
	if got := c.DaysEarly(c.DueDate().AddDate(0, 0, 3)); got != 0 {
		t.Fatalf("DaysEarly(late) = %d, want 0", got)
	}
}

// TestRoundDivZeroDen covers the defensive zero-denominator guard in roundDiv so a
// future call site that passes a zero divisor can never panic on integer division.
func TestRoundDivZeroDen(t *testing.T) {
	t.Parallel()
	if got := roundDiv(5, 0); got != 0 {
		t.Fatalf("roundDiv(5,0) = %d, want 0", got)
	}
	if got := roundDiv(5, 2); got != 3 { // (5 + 1) / 2 = 3 (half-up)
		t.Fatalf("roundDiv(5,2) = %d, want 3", got)
	}
}
