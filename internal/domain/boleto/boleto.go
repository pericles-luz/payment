// Package boleto holds the BolePix domain: a boleto (bank slip) with a due date
// and the rules that compute how much is owed when it is paid late — the one-time
// fine (multa) and the pro-rata-die mora interest (juros). These rules are PURE
// domain: they never touch the network or the PSP. The C6 adapter only registers
// the boleto's parameters with the bank; deciding what is owed at a given instant
// is the domain's responsibility (Hexagonal).
package boleto

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

const (
	// MaxFineBps caps the one-time fine (multa por atraso) at 2% of the principal,
	// the ceiling Brazilian consumer law (Lei 9.298/96, art. 1º) allows on a
	// consumer debt. 1 bp = 0.01%, so 2% = 200 bp.
	MaxFineBps = 200
	// MaxMonthlyInterestBps caps the mora interest at 1% per month (the common
	// legal ceiling for juros de mora). Daily accrual is pro rata die: the monthly
	// rate divided across the days in the reference month.
	MaxMonthlyInterestBps = 100

	// bpsDenominator turns a basis-point rate into a fraction (value/10000).
	bpsDenominator = 10000
	// daysPerMonth is the divisor used for pro-rata-die mora interest, the market
	// convention for boletos in Brazil (taxa mensal / 30 × dias de atraso).
	daysPerMonth = 30
)

// DiscountTier is one step of an early-payment discount schedule (roteiro grupo 3).
// A payer who settles the boleto at least DaysBeforeDue days before the due date
// earns this tier's discount. A tier carries EITHER a percentage (Bps, basis points
// of the principal) OR a fixed amount (FixedCents) — never both. A single tier with
// DaysBeforeDue == 0 expresses "desconto até o vencimento" (3.a); several ordered
// tiers express the escalonado-por-dias schedule (3.b).
type DiscountTier struct {
	// DaysBeforeDue is the minimum number of whole days before the due date the
	// payment must occur for this tier to apply. 0 means "any time up to and
	// including the due date".
	DaysBeforeDue int
	// Bps is the discount as basis points of the principal (1 bp = 0.01%). Mutually
	// exclusive with FixedCents.
	Bps int64
	// FixedCents is the discount as a fixed amount in cents. Mutually exclusive with
	// Bps.
	FixedCents int64
}

// cents returns the tier's discount value in cents for the given principal. It is
// only called after validation has guaranteed exactly one of Bps/FixedCents is set
// and the result is strictly less than the principal.
func (d DiscountTier) cents(principalCents int64) int64 {
	if d.FixedCents > 0 {
		return d.FixedCents
	}
	return roundDiv(principalCents*d.Bps, bpsDenominator)
}

// Boleto is a registered bank slip. It is immutable once constructed; the amount
// owed is derived from the principal, the late-payment rules and the payment
// instant, never stored as mutable state.
type Boleto struct {
	id                 string
	tenantID           string
	principal          shared.Money
	dueDate            time.Time
	fineBps            int64
	fineFixedCents     int64
	monthlyInterestBps int64
	// validUntil is the last day the boleto may be paid (data limite de pagamento),
	// distinct from the due date: late payment is still accepted up to this instant.
	// Zero means "unset" (payment accepted indefinitely after the due date).
	validUntil time.Time
	// discounts is the early-payment discount schedule, ordered strictly descending
	// by DaysBeforeDue (largest discount first). Empty when the boleto carries no
	// discount. Always validated by WithDiscounts before being attached.
	discounts []DiscountTier
}

// New constructs a Boleto, enforcing the domain invariants: identifiers present,
// a positive principal (guaranteed by shared.Money), a real due date, and fine /
// interest rates within their legal ceilings. Rates are accepted in basis points
// so the rule is expressed in exact integers, never floats.
func New(id, tenantID string, principal shared.Money, dueDate time.Time, fineBps, monthlyInterestBps int64) (Boleto, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Boleto{}, shared.NewValidationError("id", "boleto id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Boleto{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	if principal.IsZero() {
		return Boleto{}, shared.NewValidationError("principal", "principal amount is required")
	}
	if dueDate.IsZero() {
		return Boleto{}, shared.NewValidationError("due_date", "due date is required")
	}
	if fineBps < 0 || fineBps > MaxFineBps {
		return Boleto{}, shared.NewValidationError("fine_bps", "fine must be between 0 and 200 basis points (0–2%)")
	}
	if monthlyInterestBps < 0 || monthlyInterestBps > MaxMonthlyInterestBps {
		return Boleto{}, shared.NewValidationError("monthly_interest_bps", "monthly interest must be between 0 and 100 basis points (0–1%)")
	}
	return Boleto{
		id:                 id,
		tenantID:           tenantID,
		principal:          principal,
		dueDate:            dueDate,
		fineBps:            fineBps,
		monthlyInterestBps: monthlyInterestBps,
	}, nil
}

// WithDiscounts returns a copy of the boleto carrying the validated early-payment
// discount schedule (roteiro grupo 3). It enforces the schedule invariants in the
// core (never in a handler): each tier sets exactly one of Bps/FixedCents to a
// positive value, each discount is strictly less than the principal (so the amount
// owed stays positive), and the tiers are ordered strictly descending by
// DaysBeforeDue with a strictly decreasing discount — more days early must never be
// worth less than fewer days early. Passing no tiers returns the boleto unchanged.
func (b Boleto) WithDiscounts(tiers ...DiscountTier) (Boleto, error) {
	if len(tiers) == 0 {
		return b, nil
	}
	principal := b.principal.Cents()
	prevDays := int(^uint(0) >> 1) // max int: the first tier may use any DaysBeforeDue
	var prevCents int64 = principal + 1
	out := make([]DiscountTier, 0, len(tiers))
	for i, d := range tiers {
		if d.DaysBeforeDue < 0 {
			return Boleto{}, shared.NewValidationError("discount.days_before_due", "days before due must not be negative")
		}
		if (d.Bps > 0) == (d.FixedCents > 0) {
			return Boleto{}, shared.NewValidationError("discount", "each tier must set exactly one of bps or fixed_cents")
		}
		if d.Bps < 0 || d.FixedCents < 0 {
			return Boleto{}, shared.NewValidationError("discount", "discount values must not be negative")
		}
		if d.Bps > bpsDenominator {
			return Boleto{}, shared.NewValidationError("discount.bps", "discount must not exceed 100%")
		}
		c := d.cents(principal)
		if c <= 0 || c >= principal {
			return Boleto{}, shared.NewValidationError("discount", "discount must be positive and strictly less than the principal")
		}
		if i > 0 {
			if d.DaysBeforeDue >= prevDays {
				return Boleto{}, shared.NewValidationError("discount.days_before_due", "tiers must be ordered strictly descending by days before due")
			}
			if c >= prevCents {
				return Boleto{}, shared.NewValidationError("discount", "fewer days early must earn a strictly smaller discount")
			}
		}
		prevDays = d.DaysBeforeDue
		prevCents = c
		out = append(out, d)
	}
	b.discounts = out
	return b, nil
}

// WithFixedFine returns a copy of the boleto whose late-payment fine (multa) is a
// fixed amount in cents instead of a percentage (roteiro 2.c — "multa percentual ou
// valor fixo"). The two forms are mutually exclusive: a boleto already carrying a
// percentage fine (fineBps > 0) cannot also take a fixed fine. The fixed fine must be
// positive and must not exceed the legal 2%-of-principal ceiling (Lei 9.298/96), the
// same cap MaxFineBps enforces on the percentage form.
func (b Boleto) WithFixedFine(cents int64) (Boleto, error) {
	if b.fineBps > 0 {
		return Boleto{}, shared.NewValidationError("fine_fixed_cents", "a boleto cannot carry both a percentage and a fixed fine")
	}
	if cents <= 0 {
		return Boleto{}, shared.NewValidationError("fine_fixed_cents", "fixed fine must be positive")
	}
	maxFixed := roundDiv(b.principal.Cents()*MaxFineBps, bpsDenominator)
	if cents > maxFixed {
		return Boleto{}, shared.NewValidationError("fine_fixed_cents", "fixed fine must not exceed 2% of the principal")
	}
	b.fineFixedCents = cents
	return b, nil
}

// WithValidUntil returns a copy of the boleto carrying a payment-validity limit
// (data limite de pagamento, roteiro 5.b). The invariant lives in the core: the limit
// must not fall before the due date — a boleto cannot stop being payable before it is
// even due.
func (b Boleto) WithValidUntil(t time.Time) (Boleto, error) {
	if t.IsZero() {
		return Boleto{}, shared.NewValidationError("valid_until", "valid until is required")
	}
	if startOfDay(t).Before(startOfDay(b.dueDate)) {
		return Boleto{}, shared.NewValidationError("valid_until", "valid until must not be before the due date")
	}
	b.validUntil = t
	return b, nil
}

// ID returns the boleto identifier.
func (b Boleto) ID() string { return b.id }

// ValidUntil returns the payment-validity limit (data limite de pagamento), or the
// zero time when unset.
func (b Boleto) ValidUntil() time.Time { return b.validUntil }

// FineFixedCents returns the fixed late-payment fine in cents, or 0 when the fine is
// expressed as a percentage (FineBps) or absent.
func (b Boleto) FineFixedCents() int64 { return b.fineFixedCents }

// Discounts returns the boleto's early-payment discount schedule (may be empty).
func (b Boleto) Discounts() []DiscountTier { return b.discounts }

// TenantID returns the owning tenant.
func (b Boleto) TenantID() string { return b.tenantID }

// Principal returns the original amount owed (before fine/interest).
func (b Boleto) Principal() shared.Money { return b.principal }

// DueDate returns the due date (vencimento).
func (b Boleto) DueDate() time.Time { return b.dueDate }

// FineBps returns the one-time fine rate in basis points.
func (b Boleto) FineBps() int64 { return b.fineBps }

// MonthlyInterestBps returns the monthly mora interest rate in basis points.
func (b Boleto) MonthlyInterestBps() int64 { return b.monthlyInterestBps }

// DaysLate returns the number of whole days between the due date and the payment
// instant, never negative. Payment on (or before) the due date is zero days late.
// Both instants are reduced to their calendar day in their own location, so a
// payment at 23:59 on the due date is still on time.
func (b Boleto) DaysLate(at time.Time) int {
	diff := startOfDay(at).Sub(startOfDay(b.dueDate))
	days := int(diff / (24 * time.Hour))
	if days < 0 {
		return 0
	}
	return days
}

// FineCents returns the one-time fine owed if the boleto is paid late, else 0. The
// fine is charged in full on the first day of lateness and does not accrue. It is the
// fixed amount when one was set (roteiro 2.c), otherwise the percentage of principal.
func (b Boleto) FineCents(at time.Time) int64 {
	if b.DaysLate(at) == 0 {
		return 0
	}
	if b.fineFixedCents > 0 {
		return b.fineFixedCents
	}
	return roundDiv(b.principal.Cents()*b.fineBps, bpsDenominator)
}

// InterestCents returns the mora interest owed at the payment instant, accrued
// pro rata die: principal × monthlyRate / 30 × daysLate. It is zero when the
// boleto is paid on time.
func (b Boleto) InterestCents(at time.Time) int64 {
	days := int64(b.DaysLate(at))
	if days == 0 {
		return 0
	}
	return roundDiv(b.principal.Cents()*b.monthlyInterestBps*days, bpsDenominator*daysPerMonth)
}

// DaysEarly returns the number of whole days the payment instant falls before the
// due date, never negative. A payment on (or after) the due date is zero days early.
func (b Boleto) DaysEarly(at time.Time) int {
	diff := startOfDay(b.dueDate).Sub(startOfDay(at))
	days := int(diff / (24 * time.Hour))
	if days < 0 {
		return 0
	}
	return days
}

// DiscountCents returns the early-payment discount owed back to the payer at the
// payment instant (roteiro grupo 3), or 0 when none applies. A late payment never
// earns a discount. Among the qualifying tiers (DaysBeforeDue <= daysEarly) the most
// generous one wins; because the schedule is ordered descending, that is the first
// qualifying tier.
func (b Boleto) DiscountCents(at time.Time) int64 {
	if len(b.discounts) == 0 || b.DaysLate(at) > 0 {
		return 0
	}
	early := b.DaysEarly(at)
	for _, d := range b.discounts {
		if d.DaysBeforeDue <= early {
			return d.cents(b.principal.Cents())
		}
	}
	return 0
}

// AmountDueCents returns the total owed at the payment instant: principal plus fine
// plus accrued interest, minus any early-payment discount. Paid on time with no
// discount it equals the principal. Fine/interest (late) and discount (early) are
// mutually exclusive in time, so the total is always strictly positive.
func (b Boleto) AmountDueCents(at time.Time) int64 {
	return b.principal.Cents() + b.FineCents(at) + b.InterestCents(at) - b.DiscountCents(at)
}

// AmountDue returns the total owed at the payment instant as Money in the
// principal's currency. It never errors: the total is always strictly positive
// and the currency was already validated when the principal was constructed.
func (b Boleto) AmountDue(at time.Time) shared.Money {
	m, err := shared.NewMoney(b.AmountDueCents(at), b.principal.Currency())
	if err != nil {
		// Unreachable: AmountDueCents >= principal.Cents() > 0 and the currency is
		// the already-validated principal currency. Fall back to the principal
		// rather than panic so a future invariant change degrades safely.
		return b.principal
	}
	return m
}

// roundDiv divides num by den rounding half up. Both arguments are non-negative
// in every call site (amounts, rates and day counts are all >= 0).
func roundDiv(num, den int64) int64 {
	if den == 0 {
		return 0
	}
	return (num + den/2) / den
}

// startOfDay reduces an instant to midnight in its own location so day counting
// is not perturbed by the time of day.
func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}
