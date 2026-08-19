// Package checkout holds the unified C6 checkout domain: a session that bundles
// one or more line items into a single payable total with an expiry. The session
// and its invariants are PURE domain; the C6 adapter only opens the hosted
// checkout at the bank from a validated session (DDD-lite, Hexagonal).
package checkout

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// CardType is the card payment method a hosted checkout session permits. The C6
// hosted page routes the payer through the credit or debit flow accordingly
// (roteiro 9.a–9.c). It is a closed set: an unknown value is a validation error.
type CardType string

const (
	// CardCredit is a credit-card checkout (roteiro 9.a / 9.c).
	CardCredit CardType = "credit"
	// CardDebit is a debit-card checkout (roteiro 9.b).
	CardDebit CardType = "debit"
)

// ParseCardType normalises and validates a card-type string (case-insensitive,
// trimmed), rejecting anything outside the closed {credit, debit} set.
func ParseCardType(s string) (CardType, error) {
	switch CardType(strings.ToLower(strings.TrimSpace(s))) {
	case CardCredit:
		return CardCredit, nil
	case CardDebit:
		return CardDebit, nil
	default:
		return "", shared.NewValidationError("card_type", "card_type must be credit or debit")
	}
}

// valid reports whether c is a known card type.
func (c CardType) valid() bool { return c == CardCredit || c == CardDebit }

// Item is one line of a checkout session: a human description and a positive
// amount in cents. Immutable once constructed.
type Item struct {
	description string
	amountCents int64
}

// NewItem constructs a line item, requiring a description and a positive amount.
func NewItem(description string, amountCents int64) (Item, error) {
	description = strings.TrimSpace(description)
	if description == "" {
		return Item{}, shared.NewValidationError("description", "item description is required")
	}
	if amountCents <= 0 {
		return Item{}, shared.NewValidationError("amount_cents", "item amount must be greater than zero")
	}
	return Item{description: description, amountCents: amountCents}, nil
}

// Description returns the line description.
func (i Item) Description() string { return i.description }

// AmountCents returns the line amount in cents.
func (i Item) AmountCents() int64 { return i.amountCents }

// Session is a unified checkout session aggregate. The total is derived from the
// items (never stored as a separate mutable field) so it cannot drift from them.
type Session struct {
	id          string
	tenantID    string
	items       []Item
	total       shared.Money
	expiresAt   time.Time
	cardType    CardType
	requireAuth bool
	// maxInstallments is the ceiling of parcelas offered on a credit purchase.
	maxInstallments int
}

// New constructs a checkout Session, enforcing: identifiers present, at least one
// item, a real expiry, and a positive total in a valid currency. The total is
// summed from the items and validated through shared.Money (which rejects a
// non-positive total or a malformed ISO-4217 currency).
func New(id, tenantID, currency string, items []Item, expiresAt time.Time) (Session, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Session{}, shared.NewValidationError("id", "session id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Session{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	if len(items) == 0 {
		return Session{}, shared.NewValidationError("items", "at least one item is required")
	}
	if expiresAt.IsZero() {
		return Session{}, shared.NewValidationError("expires_at", "expiry is required")
	}

	var sum int64
	for _, it := range items {
		var err error
		if sum, err = shared.AddCents(sum, it.amountCents); err != nil {
			return Session{}, err
		}
	}
	total, err := shared.NewMoney(sum, currency)
	if err != nil {
		return Session{}, err
	}

	// Defensive copy so the caller's slice cannot mutate the session's items.
	owned := make([]Item, len(items))
	copy(owned, items)

	return Session{
		id:        id,
		tenantID:  tenantID,
		items:     owned,
		total:     total,
		expiresAt: expiresAt,
	}, nil
}

// ID returns the session identifier.
func (s Session) ID() string { return s.id }

// TenantID returns the owning tenant.
func (s Session) TenantID() string { return s.tenantID }

// Items returns a copy of the session's line items.
func (s Session) Items() []Item {
	out := make([]Item, len(s.items))
	copy(out, s.items)
	return out
}

// Total returns the payable total as Money.
func (s Session) Total() shared.Money { return s.total }

// TotalCents returns the payable total in cents.
func (s Session) TotalCents() int64 { return s.total.Cents() }

// Currency returns the session currency.
func (s Session) Currency() string { return s.total.Currency() }

// DefaultInstallments is a single payment — the value used when the caller says
// nothing, so an absent field never changes what the PSP receives today.
const DefaultInstallments = 1

// MaxInstallmentsLimit is the documented C6 ceiling for payment.card.installments.
// Enforced here because the PSP accepts values beyond it (see WithCard).
const MaxInstallmentsLimit = 12

// ExpiresAt returns the expiry instant.
func (s Session) ExpiresAt() time.Time { return s.expiresAt }

// CardType returns the permitted card payment method (empty until set via WithCard).
func (s Session) CardType() CardType { return s.cardType }

// RequireAuthentication reports whether the hosted page must authenticate the
// payer (step-up / 3-DS) before capture (roteiro 9.c).
func (s Session) RequireAuthentication() bool { return s.requireAuth }

// WithCard returns a copy of the session carrying the permitted card type and
// whether the hosted page must authenticate the payer. It validates the card
// type (the only closed-set field) and is the canonical way to attach the
// payment-method routing to a validated session, keeping New's signature stable.
// The value-receiver copy keeps Session effectively immutable.
// maxInstallments is the ceiling of parcelas the buyer may split a credit purchase
// into. Zero/absent means a single payment, which keeps the request byte-identical to
// what this adapter has always sent.
//
// THE RANGE AND THE DEBIT RULE ARE OURS TO ENFORCE. Probed against the live C6 on
// 2026-08-19: a create with installments: 13 answered 201, and so did a DEBIT card
// with 3 parcelas. The PSP validates neither, so an out-of-range value would sail
// through creation and only misbehave when a real buyer tries to pay — the worst
// possible place to discover it. What C6 does reject is the amount: below R$ 5,00 it
// answers 400 naming /amount and minimum 5.
func (s Session) WithCard(card CardType, requireAuth bool, maxInstallments int) (Session, error) {
	if !card.valid() {
		return Session{}, shared.NewValidationError("card_type", "card_type must be credit or debit")
	}
	maxInstallments, err := NormalizeInstallments(card, maxInstallments)
	if err != nil {
		return Session{}, err
	}
	s.cardType = card
	s.requireAuth = requireAuth
	s.maxInstallments = maxInstallments
	return s, nil
}

// NormalizeInstallments validates the requested ceiling against the card type and
// returns the value to use. It is exported so the caller can reject a bad request
// BEFORE reserving a payment and billing the tenant — WithCard calls it too, so the
// invariant holds even for a caller that skips the early check.
func NormalizeInstallments(card CardType, maxInstallments int) (int, error) {
	if maxInstallments <= 0 {
		return DefaultInstallments, nil
	}
	if maxInstallments > MaxInstallmentsLimit {
		return 0, shared.NewValidationError("max_installments",
			"max_installments must be between 1 and 12")
	}
	if card == CardDebit && maxInstallments > 1 {
		return 0, shared.NewValidationError("max_installments",
			"debit card cannot be split into installments")
	}
	return maxInstallments, nil
}

// MinInstallmentCents is the PSP's floor for EACH parcela: R$ 5,00. It is the same
// number as the checkout total minimum, and not a coincidence — a single-payment
// purchase is one parcela.
const MinInstallmentCents int64 = 500

// AffordableInstallments caps a requested ceiling at what the total can actually be
// split into: each parcela must clear MinInstallmentCents.
//
// This rule is NOT enforced when the session is created. Probed against the live C6:
// R$ 6,00 split in 3x (R$ 2,00 a parcela) answered 201, and R$ 15,00 in 6x answered
// 201 too — and then the hosted page refused with "Link de Pagamento não encontrado".
// So the PSP accepts the session and breaks at the worst possible moment: with the
// buyer already on the payment page, holding a link that will never work.
//
// Capping here turns that into an offer the buyer can actually take: a R$ 30,00
// purchase offers up to 6x, a R$ 15,00 one up to 3x, and a R$ 4,00 one is not a card
// purchase at all (the total minimum already refuses it).
func AffordableInstallments(totalCents int64, maxInstallments int) int {
	if maxInstallments <= 1 || totalCents <= 0 {
		return DefaultInstallments
	}
	cabem := int(totalCents / MinInstallmentCents)
	if cabem < DefaultInstallments {
		return DefaultInstallments
	}
	if cabem < maxInstallments {
		return cabem
	}
	return maxInstallments
}

// MaxInstallments returns the ceiling of parcelas offered to the buyer (1 when the
// purchase is a single payment).
func (s Session) MaxInstallments() int { return s.maxInstallments }

// IsExpired reports whether the session has expired at instant at (expiry is
// exclusive: a session is live up to and including its expiry instant).
func (s Session) IsExpired(at time.Time) bool { return at.After(s.expiresAt) }
