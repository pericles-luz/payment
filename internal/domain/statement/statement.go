// Package statement holds the account-statement (extrato) domain (roteiro grupo
// 13): the entries posted to a tenant's account over a period. The aggregate OWNS
// its invariants — the period is valid only when fim >= inicio and the window does
// not exceed 30 days (the bank caps an extrato query at 30 days), and every entry
// is well-formed — as PURE domain: it never touches the network or the PSP. The
// adapter only transports the entries; deciding whether a requested period is legal
// is the domain's responsibility (Hexagonal), enforced before the use-case ever
// reaches the bank.
package statement

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// MaxPeriod is the largest extrato window the bank accepts (roteiro 13.a: máx. 30
// dias). It bounds the span between inicio and fim — the difference fim-inicio must
// not exceed it. A query whose inicio equals its fim (a single day) is the smallest
// legal window.
const MaxPeriod = 30 * 24 * time.Hour

// EntryKind is the direction of a statement entry: a credit (money in) or a debit
// (money out). It is a closed set; an unknown value is rejected at construction so
// an entry can never hold a direction the domain has no meaning for.
type EntryKind string

const (
	// KindCredit is a credit entry (lançamento de crédito): money posted into the
	// account.
	KindCredit EntryKind = "credit"
	// KindDebit is a debit entry (lançamento de débito): money posted out of the
	// account.
	KindDebit EntryKind = "debit"
)

// ParseEntryKind normalises and validates an entry-kind string (trimmed), rejecting
// anything outside the closed set.
func ParseEntryKind(s string) (EntryKind, error) {
	switch EntryKind(strings.TrimSpace(s)) {
	case KindCredit:
		return KindCredit, nil
	case KindDebit:
		return KindDebit, nil
	default:
		return "", shared.NewValidationError("entry.kind", "unknown statement entry kind")
	}
}

// Period is a validated extrato date window [start, end]. It is a value object: the
// only way to build one is NewPeriod, which enforces the invariants, so a Period
// that exists is always legal to query.
type Period struct {
	start time.Time
	end   time.Time
}

// NewPeriod builds a Period, enforcing the extrato invariants: both bounds are
// required, fim must not precede inicio, and the window must not exceed MaxPeriod
// (30 days). Each violation is a distinct shared.ErrValidation so the boundary can
// surface a precise 400/422.
func NewPeriod(start, end time.Time) (Period, error) {
	if start.IsZero() {
		return Period{}, shared.NewValidationError("inicio", "start date is required")
	}
	if end.IsZero() {
		return Period{}, shared.NewValidationError("fim", "end date is required")
	}
	if end.Before(start) {
		return Period{}, shared.NewValidationError("fim", "end date must not precede start date")
	}
	if end.Sub(start) > MaxPeriod {
		return Period{}, shared.NewValidationError("fim", "period must not exceed 30 days")
	}
	return Period{start: start, end: end}, nil
}

// Start returns the inicio bound.
func (p Period) Start() time.Time { return p.start }

// End returns the fim bound.
func (p Period) End() time.Time { return p.end }

// Entry is one posted line of an account statement: the bank's entry id, the date it
// was posted, the amount in cents, its direction and a short description (histórico).
// It is a read projection; immutable once built.
type Entry struct {
	id          string
	date        time.Time
	amountCents int64
	kind        EntryKind
	description string
}

// NewEntry builds an Entry, validating the id, a real posting date, a positive
// amount, a known direction and a non-empty description. The amount is always
// positive; the direction (credit/debit) carries the sign meaning, so a debit is
// not encoded as a negative amount.
func NewEntry(id string, date time.Time, amountCents int64, kind EntryKind, description string) (Entry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Entry{}, shared.NewValidationError("entry.id", "entry id is required")
	}
	if date.IsZero() {
		return Entry{}, shared.NewValidationError("entry.date", "entry date is required")
	}
	if amountCents <= 0 {
		return Entry{}, shared.NewValidationError("entry.amount_cents", "amount must be greater than zero")
	}
	k, err := ParseEntryKind(string(kind))
	if err != nil {
		return Entry{}, err
	}
	description = strings.TrimSpace(description)
	if description == "" {
		return Entry{}, shared.NewValidationError("entry.description", "description is required")
	}
	return Entry{id: id, date: date, amountCents: amountCents, kind: k, description: description}, nil
}

// ID returns the bank's entry id.
func (e Entry) ID() string { return e.id }

// Date returns the posting date.
func (e Entry) Date() time.Time { return e.date }

// AmountCents returns the (positive) entry amount in cents.
func (e Entry) AmountCents() int64 { return e.amountCents }

// Kind returns the entry direction (credit/debit).
func (e Entry) Kind() EntryKind { return e.kind }

// Description returns the entry's short description (histórico).
func (e Entry) Description() string { return e.description }

// Statement is the account-statement aggregate for a tenant over a period: the
// validated window plus the entries posted within it. It is built through New, which
// rejects a missing tenant and takes ownership of a copy of the entries so a later
// mutation of the caller's slice cannot reach into the aggregate.
type Statement struct {
	tenantID string
	period   Period
	entries  []Entry
}

// New builds a Statement for tenantID over period with entries. The tenant id is
// required (an extrato is always the authenticated tenant's, never client input);
// the entries are copied defensively.
func New(tenantID string, period Period, entries []Entry) (Statement, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Statement{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	owned := make([]Entry, len(entries))
	copy(owned, entries)
	return Statement{tenantID: tenantID, period: period, entries: owned}, nil
}

// TenantID returns the owning tenant.
func (s Statement) TenantID() string { return s.tenantID }

// Period returns the statement's validated window.
func (s Statement) Period() Period { return s.period }

// Entries returns a copy of the statement's entries.
func (s Statement) Entries() []Entry {
	out := make([]Entry, len(s.entries))
	copy(out, s.entries)
	return out
}
