// Package pixcobv holds the PIX cobrança-com-vencimento (cobv) domain: a PIX
// charge with a due date (vencimento) and the rules that decide how much is owed
// when it is paid — the one-time fine (multa), the pro-rata-die mora interest
// (juros) and the early-payment discount (desconto). These rules are PURE domain:
// they never touch the network or the PSP. The C6 adapter only registers the
// charge's parameters with the bank; deciding what is owed at a given instant and
// whether the charge is still payable is the domain's responsibility (Hexagonal).
//
// It is the vencimento counterpart of the immediate PIX charge (cobrança imediata,
// roteiro 7.1–7.4): an immediate charge expires by a QR lifetime, a cobv charge has
// a calendar due date plus a validity window after it (roteiro 7.5–7.7).
package pixcobv

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

const (
	// MaxFineBps caps the one-time fine (multa por atraso) at 2% of the principal,
	// the ceiling Brazilian consumer law (Lei 9.298/96, art. 1º) allows on a consumer
	// debt. 1 bp = 0.01%, so 2% = 200 bp. It mirrors the boleto domain's cap: a cobv
	// and a boleto are the same debt expressed over PIX vs the bank slip.
	MaxFineBps = 200
	// MaxMonthlyInterestBps caps the mora interest at 1% per month (the common legal
	// ceiling for juros de mora). Daily accrual is pro rata die: the monthly rate
	// divided across the days in the reference month.
	MaxMonthlyInterestBps = 100

	// bpsDenominator turns a basis-point rate into a fraction (value/10000).
	bpsDenominator = 10000
	// daysPerMonth is the divisor used for pro-rata-die mora interest, the market
	// convention in Brazil (taxa mensal / 30 × dias de atraso).
	daysPerMonth = 30
)

// DebtorType classifies the payer (devedor) by document: pessoa física (CPF, 11
// digits) or pessoa jurídica (CNPJ, 14 digits). It is derived from the document
// length, never trusted from the caller.
type DebtorType string

const (
	// DebtorPF is a pessoa física payer (CPF).
	DebtorPF DebtorType = "PF"
	// DebtorPJ is a pessoa jurídica payer (CNPJ).
	DebtorPJ DebtorType = "PJ"
)

// Debtor identifies the payer of a cobv charge. A cobv always carries a devedor
// (unlike an immediate charge, where it is optional): the document is a CPF or CNPJ
// and the name is required. The document is never logged.
type Debtor struct {
	taxID   string
	name    string
	street  string
	city    string
	state   string
	zipCode string
}

// TaxID returns the payer document (all digits, CPF or CNPJ).
func (d Debtor) TaxID() string { return d.taxID }

// Street, City, State and ZipCode return the payer address the PSP requires on a
// due-date charge.
func (d Debtor) Street() string  { return d.street }
func (d Debtor) City() string    { return d.city }
func (d Debtor) State() string   { return d.state }
func (d Debtor) ZipCode() string { return d.zipCode }

// Name returns the payer name.
func (d Debtor) Name() string { return d.name }

// Type reports whether the payer is a pessoa física (CPF) or jurídica (CNPJ),
// derived from the document length validated at construction.
func (d Debtor) Type() DebtorType {
	if len(d.taxID) == 14 {
		return DebtorPJ
	}
	return DebtorPF
}

// Charge is a registered PIX charge with a due date. It is immutable once
// constructed; the amount owed is derived from the principal, the late/early rules
// and the payment instant, never stored as mutable state.
type Charge struct {
	tenantID           string
	principal          shared.Money
	dueDate            time.Time
	validityDays       int
	fineBps            int64
	monthlyInterestBps int64
	discountBps        int64
	discountFixedCents int64
	debtor             Debtor
	creditorKey        string
}

// Params is the validated parameter set for a cobv charge. It is the single input
// shared by registration and amendment so both go through one validation path.
type Params struct {
	TenantID           string
	Principal          shared.Money
	DueDate            time.Time
	ValidityDays       int
	FineBps            int64
	MonthlyInterestBps int64
	DiscountBps        int64
	DiscountFixedCents int64
	DebtorTaxID        string
	DebtorName         string
	DebtorStreet       string
	DebtorCity         string
	DebtorState        string
	DebtorZipCode      string
	CreditorKey        string
}

// New constructs a Charge, enforcing the cobv invariants in the core: identifiers
// and creditor key present, a positive principal (guaranteed by shared.Money), a
// real due date, a non-negative validity window, fine/interest within their legal
// ceilings, a well-formed discount strictly below the principal, and a devedor with
// a valid CPF/CNPJ and a name. Rates are basis points so the rule is exact integers,
// never floats. Whether the due date is in the future is a clock-dependent boundary
// check enforced by the use-case, not here (the domain stays pure/deterministic).
func New(p Params) (Charge, error) {
	tenantID := strings.TrimSpace(p.TenantID)
	if tenantID == "" {
		return Charge{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	if p.Principal.IsZero() {
		return Charge{}, shared.NewValidationError("principal", "principal amount is required")
	}
	if p.DueDate.IsZero() {
		return Charge{}, shared.NewValidationError("due_date", "due date is required")
	}
	if p.ValidityDays < 0 {
		return Charge{}, shared.NewValidationError("validity_days", "validity after due date must not be negative")
	}
	if p.FineBps < 0 || p.FineBps > MaxFineBps {
		return Charge{}, shared.NewValidationError("fine_bps", "fine must be between 0 and 200 basis points (0–2%)")
	}
	if p.MonthlyInterestBps < 0 || p.MonthlyInterestBps > MaxMonthlyInterestBps {
		return Charge{}, shared.NewValidationError("monthly_interest_bps", "monthly interest must be between 0 and 100 basis points (0–1%)")
	}
	if err := validateDiscount(p.DiscountBps, p.DiscountFixedCents, p.Principal.Cents()); err != nil {
		return Charge{}, err
	}
	debtor, err := newDebtor(p.DebtorTaxID, p.DebtorName, p.DebtorStreet, p.DebtorCity, p.DebtorState, p.DebtorZipCode)
	if err != nil {
		return Charge{}, err
	}
	creditorKey := strings.TrimSpace(p.CreditorKey)
	if creditorKey == "" {
		return Charge{}, shared.NewValidationError("creditor_key", "creditor pix key is required")
	}
	return Charge{
		tenantID:           tenantID,
		principal:          p.Principal,
		dueDate:            p.DueDate,
		validityDays:       p.ValidityDays,
		fineBps:            p.FineBps,
		monthlyInterestBps: p.MonthlyInterestBps,
		discountBps:        p.DiscountBps,
		discountFixedCents: p.DiscountFixedCents,
		debtor:             debtor,
		creditorKey:        creditorKey,
	}, nil
}

// validateDiscount enforces that at most one discount form is set and, when set, it
// is positive and strictly less than the principal so the amount owed stays
// positive. A bps discount must not exceed 100%.
func validateDiscount(bps, fixedCents, principalCents int64) error {
	if bps == 0 && fixedCents == 0 {
		return nil
	}
	if bps > 0 && fixedCents > 0 {
		return shared.NewValidationError("discount", "set at most one of discount_bps or discount_fixed_cents")
	}
	if bps < 0 || fixedCents < 0 {
		return shared.NewValidationError("discount", "discount values must not be negative")
	}
	if bps > bpsDenominator {
		return shared.NewValidationError("discount_bps", "discount must not exceed 100%")
	}
	c := discountCents(bps, fixedCents, principalCents)
	if c <= 0 || c >= principalCents {
		return shared.NewValidationError("discount", "discount must be positive and strictly less than the principal")
	}
	return nil
}

// newDebtor validates and builds the devedor: a required CPF (11) or CNPJ (14)
// all-digit document and a required name. The check is syntactic (length + digits),
// mirroring the immediate-charge devedor guard.
func newDebtor(taxID, name, street, city, state, zipCode string) (Debtor, error) {
	taxID = strings.TrimSpace(taxID)
	name = strings.TrimSpace(name)
	street = strings.TrimSpace(street)
	city = strings.TrimSpace(city)
	state = strings.TrimSpace(state)
	zipCode = strings.TrimSpace(zipCode)
	if !validTaxID(taxID) {
		return Debtor{}, shared.NewValidationError("devedor.tax_id", "debtor tax id must be 11 (CPF) or 14 (CNPJ) digits")
	}
	if name == "" {
		return Debtor{}, shared.NewValidationError("devedor.name", "debtor name is required")
	}
	// The address is required by the PSP on every cobv. Validating it here — where the
	// charge is already validated — turns a bank-side 400 into a named field error at our
	// boundary, before any money-moving call is attempted.
	for _, f := range []struct{ field, value string }{
		{"devedor.logradouro", street},
		{"devedor.cidade", city},
		{"devedor.uf", state},
		{"devedor.cep", zipCode},
	} {
		if f.value == "" {
			return Debtor{}, shared.NewValidationError(f.field, "debtor address is required on a due-date charge")
		}
	}
	return Debtor{taxID: taxID, name: name, street: street, city: city, state: state, zipCode: zipCode}, nil
}

// validTaxID reports whether s is an all-digit CPF (11) or CNPJ (14). It is a
// syntactic check (length + digits), not a check-digit validation.
func validTaxID(s string) bool {
	if len(s) != 11 && len(s) != 14 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// TenantID returns the owning tenant.
func (c Charge) TenantID() string { return c.tenantID }

// Principal returns the original amount owed (before fine/interest/discount).
func (c Charge) Principal() shared.Money { return c.principal }

// DueDate returns the due date (vencimento).
func (c Charge) DueDate() time.Time { return c.dueDate }

// ValidityDays returns the number of days after the due date the charge may still
// be paid (validade após vencimento). Zero means it is payable only up to the due
// date.
func (c Charge) ValidityDays() int { return c.validityDays }

// FineBps returns the one-time fine rate in basis points.
func (c Charge) FineBps() int64 { return c.fineBps }

// MonthlyInterestBps returns the monthly mora interest rate in basis points.
func (c Charge) MonthlyInterestBps() int64 { return c.monthlyInterestBps }

// DiscountBps returns the early-payment discount rate in basis points (0 when the
// discount is a fixed amount or absent).
func (c Charge) DiscountBps() int64 { return c.discountBps }

// DiscountFixedCents returns the early-payment discount as a fixed amount in cents
// (0 when the discount is a percentage or absent).
func (c Charge) DiscountFixedCents() int64 { return c.discountFixedCents }

// Debtor returns the payer (devedor).
func (c Charge) Debtor() Debtor { return c.debtor }

// CreditorKey returns the creditor's PIX key (chave do recebedor).
func (c Charge) CreditorKey() string { return c.creditorKey }

// PayableUntil returns the last instant the charge may be paid: the due date plus
// the validity window (validade após vencimento).
func (c Charge) PayableUntil() time.Time {
	return startOfDay(c.dueDate).AddDate(0, 0, c.validityDays)
}

// Expired reports whether the payment instant falls strictly after the validity
// window — the charge can no longer be paid.
func (c Charge) Expired(at time.Time) bool {
	return startOfDay(at).After(c.PayableUntil())
}

// DaysLate returns the whole days between the due date and the payment instant,
// never negative. Payment on or before the due date is zero days late.
func (c Charge) DaysLate(at time.Time) int {
	diff := startOfDay(at).Sub(startOfDay(c.dueDate))
	days := int(diff / (24 * time.Hour))
	if days < 0 {
		return 0
	}
	return days
}

// DaysEarly returns the whole days the payment instant falls before the due date,
// never negative. Payment on or after the due date is zero days early.
func (c Charge) DaysEarly(at time.Time) int {
	diff := startOfDay(c.dueDate).Sub(startOfDay(at))
	days := int(diff / (24 * time.Hour))
	if days < 0 {
		return 0
	}
	return days
}

// FineCents returns the one-time fine owed if the charge is paid late, else 0. The
// fine is charged in full on the first day of lateness and does not accrue.
func (c Charge) FineCents(at time.Time) int64 {
	if c.DaysLate(at) == 0 {
		return 0
	}
	return roundDiv(c.principal.Cents()*c.fineBps, bpsDenominator)
}

// InterestCents returns the mora interest owed at the payment instant, accrued pro
// rata die: principal × monthlyRate / 30 × daysLate. Zero when paid on time.
func (c Charge) InterestCents(at time.Time) int64 {
	days := int64(c.DaysLate(at))
	if days == 0 {
		return 0
	}
	return roundDiv(c.principal.Cents()*c.monthlyInterestBps*days, bpsDenominator*daysPerMonth)
}

// DiscountCents returns the early-payment discount owed back to the payer at the
// payment instant, or 0 when none applies. A late payment never earns a discount;
// the discount applies any time up to and including the due date (desconto até o
// vencimento).
func (c Charge) DiscountCents(at time.Time) int64 {
	if c.DaysLate(at) > 0 {
		return 0
	}
	return discountCents(c.discountBps, c.discountFixedCents, c.principal.Cents())
}

// AmountDueCents returns the total owed at the payment instant: principal plus fine
// plus accrued interest, minus any early-payment discount. Fine/interest (late) and
// discount (early) are mutually exclusive in time, so the total is always strictly
// positive.
func (c Charge) AmountDueCents(at time.Time) int64 {
	return c.principal.Cents() + c.FineCents(at) + c.InterestCents(at) - c.DiscountCents(at)
}

// AmountDue returns the total owed at the payment instant as Money in the
// principal's currency. It never errors: the total is always strictly positive and
// the currency was already validated when the principal was constructed.
func (c Charge) AmountDue(at time.Time) shared.Money {
	m, err := shared.NewMoney(c.AmountDueCents(at), c.principal.Currency())
	if err != nil {
		return c.principal
	}
	return m
}

// discountCents returns the discount value in cents for the principal, given the
// (mutually exclusive) bps/fixed forms. The fixed form wins when set.
func discountCents(bps, fixedCents, principalCents int64) int64 {
	if fixedCents > 0 {
		return fixedCents
	}
	return roundDiv(principalCents*bps, bpsDenominator)
}

// roundDiv divides num by den rounding half up. Both arguments are non-negative in
// every call site (amounts, rates and day counts are all >= 0).
func roundDiv(num, den int64) int64 {
	if den == 0 {
		return 0
	}
	return (num + den/2) / den
}

// startOfDay reduces an instant to midnight in its own location so day counting is
// not perturbed by the time of day.
func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}
