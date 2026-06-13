// Package consent holds the PIX Automático domain: a recurring-debit
// authorization a payer grants so a tenant may debit them on a schedule, up to a
// per-cycle ceiling, within a validity window. The consent and its lifecycle are
// PURE domain — the C6 adapter merely registers/queries/cancels the consent at
// the bank; the rules about what a valid consent is and which state transitions
// are legal live here (DDD-lite, Hexagonal).
package consent

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Frequency is how often the recurring debit may occur.
type Frequency string

const (
	Weekly  Frequency = "WEEKLY"
	Monthly Frequency = "MONTHLY"
	Yearly  Frequency = "YEARLY"
)

// valid reports whether f is one of the supported recurrence frequencies.
func (f Frequency) valid() bool {
	switch f {
	case Weekly, Monthly, Yearly:
		return true
	default:
		return false
	}
}

// Status is the lifecycle state of a consent.
type Status string

const (
	// Pending is the initial state: the authorization exists but has not yet been
	// confirmed/activated by the payer's bank.
	Pending Status = "PENDING"
	// Active means the consent may be used to originate debits.
	Active Status = "ACTIVE"
	// Cancelled is terminal: no further debits may be originated.
	Cancelled Status = "CANCELLED"
)

// Consent is a recurring-debit authorization aggregate. Immutable except for the
// explicit lifecycle transitions (Activate/Cancel), which enforce legal ordering.
type Consent struct {
	id          string
	tenantID    string
	debtorTaxID string
	maxAmount   shared.Money
	frequency   Frequency
	start       time.Time
	end         time.Time // zero => open-ended
	status      Status
}

// New constructs a Consent in the Pending state, enforcing the invariants:
// identifiers present, a syntactically valid payer tax id (CPF/CNPJ digits), a
// positive per-cycle ceiling (shared.Money), a supported frequency, a real start
// instant and — when bounded — an end strictly after the start.
func New(id, tenantID, debtorTaxID string, maxAmount shared.Money, frequency Frequency, start, end time.Time) (Consent, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Consent{}, shared.NewValidationError("id", "consent id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Consent{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	debtorTaxID = strings.TrimSpace(debtorTaxID)
	if !validTaxID(debtorTaxID) {
		return Consent{}, shared.NewValidationError("debtor_tax_id", "debtor tax id must be 11 (CPF) or 14 (CNPJ) digits")
	}
	if maxAmount.IsZero() {
		return Consent{}, shared.NewValidationError("max_amount", "per-cycle ceiling is required")
	}
	if !frequency.valid() {
		return Consent{}, shared.NewValidationError("frequency", "frequency must be WEEKLY, MONTHLY or YEARLY")
	}
	if start.IsZero() {
		return Consent{}, shared.NewValidationError("start", "start is required")
	}
	if !end.IsZero() && !end.After(start) {
		return Consent{}, shared.NewValidationError("end", "end must be after start")
	}
	return Consent{
		id:          id,
		tenantID:    tenantID,
		debtorTaxID: debtorTaxID,
		maxAmount:   maxAmount,
		frequency:   frequency,
		start:       start,
		end:         end,
		status:      Pending,
	}, nil
}

// ID returns the consent identifier.
func (c Consent) ID() string { return c.id }

// TenantID returns the owning tenant.
func (c Consent) TenantID() string { return c.tenantID }

// DebtorTaxID returns the payer's CPF/CNPJ.
func (c Consent) DebtorTaxID() string { return c.debtorTaxID }

// MaxAmount returns the per-cycle debit ceiling.
func (c Consent) MaxAmount() shared.Money { return c.maxAmount }

// Frequency returns the recurrence frequency.
func (c Consent) Frequency() Frequency { return c.frequency }

// Start returns the start of the validity window.
func (c Consent) Start() time.Time { return c.start }

// End returns the end of the validity window (zero when open-ended).
func (c Consent) End() time.Time { return c.end }

// Status returns the current lifecycle state.
func (c Consent) Status() Status { return c.status }

// IsOpenEnded reports whether the consent has no end date.
func (c Consent) IsOpenEnded() bool { return c.end.IsZero() }

// WithinWindow reports whether at falls inside the consent's validity window
// (start inclusive, end inclusive when bounded).
func (c Consent) WithinWindow(at time.Time) bool {
	if at.Before(c.start) {
		return false
	}
	if !c.end.IsZero() && at.After(c.end) {
		return false
	}
	return true
}

// Covers reports whether a single debit of amountCents is permitted: it must be
// strictly positive and not exceed the per-cycle ceiling. Currency is assumed to
// match the consent (callers debit in the consent's currency).
func (c Consent) Covers(amountCents int64) bool {
	return amountCents > 0 && amountCents <= c.maxAmount.Cents()
}

// CanDebit reports whether a single recurring debit of amountCents may be
// originated against this consent at instant at. It is the single, consolidated
// secure-by-default guard that a debit-origination caller MUST use: a debit is
// authorized only when ALL of the following hold — the consent is Active, at
// falls inside the validity window, and the amount is within the per-cycle
// ceiling.
//
// Folding Status/WithinWindow/Covers into one method removes the
// insecure-by-default trap where a caller could move money by checking only a
// subset (e.g. debiting a Pending/Cancelled consent, or one outside its window).
// Prefer CanDebit over composing the three predicates by hand at debit time.
func (c Consent) CanDebit(at time.Time, amountCents int64) bool {
	return c.status == Active && c.WithinWindow(at) && c.Covers(amountCents)
}

// Activate transitions a Pending consent to Active. Activating from any other
// state is an illegal transition.
func (c *Consent) Activate() error {
	if c.status != Pending {
		return shared.ErrInvalidTransition
	}
	c.status = Active
	return nil
}

// Cancel transitions a Pending or Active consent to Cancelled. Cancelling an
// already-cancelled consent is an illegal transition.
func (c *Consent) Cancel() error {
	if c.status == Cancelled {
		return shared.ErrInvalidTransition
	}
	c.status = Cancelled
	return nil
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
