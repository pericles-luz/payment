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
	id        string
	tenantID  string
	items     []Item
	total     shared.Money
	expiresAt time.Time
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
		sum += it.amountCents
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

// ExpiresAt returns the expiry instant.
func (s Session) ExpiresAt() time.Time { return s.expiresAt }

// IsExpired reports whether the session has expired at instant at (expiry is
// exclusive: a session is live up to and including its expiry instant).
func (s Session) IsExpired(at time.Time) bool { return at.After(s.expiresAt) }
