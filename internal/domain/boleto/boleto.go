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

// Boleto is a registered bank slip. It is immutable once constructed; the amount
// owed is derived from the principal, the late-payment rules and the payment
// instant, never stored as mutable state.
type Boleto struct {
	id                 string
	tenantID           string
	principal          shared.Money
	dueDate            time.Time
	fineBps            int64
	monthlyInterestBps int64
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

// ID returns the boleto identifier.
func (b Boleto) ID() string { return b.id }

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

// FineCents returns the one-time fine owed if the boleto is paid late, else 0.
// The fine is charged in full on the first day of lateness and does not accrue.
func (b Boleto) FineCents(at time.Time) int64 {
	if b.DaysLate(at) == 0 {
		return 0
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

// AmountDueCents returns the total owed at the payment instant: principal plus
// fine plus accrued interest. Paid on time, it equals the principal.
func (b Boleto) AmountDueCents(at time.Time) int64 {
	return b.principal.Cents() + b.FineCents(at) + b.InterestCents(at)
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
