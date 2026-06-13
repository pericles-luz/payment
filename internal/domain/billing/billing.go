// Package billing holds the per-endpoint pricing and the append-only ledger of
// billable events. Pricing is resolved per tenant × endpoint. Pure domain.
package billing

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// EndpointPricing is the price (in cents) a tenant pays for one call of a given
// endpoint. It is the value behind the endpoint_pricing table.
type EndpointPricing struct {
	tenantID   string
	endpoint   string
	priceCents int64
}

// NewEndpointPricing constructs a pricing rule, enforcing invariants: a tenant,
// a non-empty endpoint and a non-negative price (zero allowed = free endpoint).
func NewEndpointPricing(tenantID, endpoint string, priceCents int64) (EndpointPricing, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return EndpointPricing{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return EndpointPricing{}, shared.NewValidationError("endpoint", "endpoint is required")
	}
	if priceCents < 0 {
		return EndpointPricing{}, shared.NewValidationError("price_cents", "price must be non-negative")
	}
	return EndpointPricing{tenantID: tenantID, endpoint: endpoint, priceCents: priceCents}, nil
}

// TenantID returns the owning tenant.
func (p EndpointPricing) TenantID() string { return p.tenantID }

// Endpoint returns the billable endpoint.
func (p EndpointPricing) Endpoint() string { return p.endpoint }

// PriceCents returns the price in cents.
func (p EndpointPricing) PriceCents() int64 { return p.priceCents }

// LedgerEntry is an immutable, append-only record that a tenant was charged the
// resolved price for a billable endpoint call. The ledger is authoritative for
// billing — never a value derived from mutable state.
type LedgerEntry struct {
	id         string
	tenantID   string
	endpoint   string
	priceCents int64
	reference  string // e.g. the payment id / idempotency key that triggered the charge
	at         time.Time
}

// NewLedgerEntry records a billable event for a tenant × endpoint at the resolved
// price. reference ties the charge to the triggering operation for auditability.
func NewLedgerEntry(id, tenantID, endpoint, reference string, priceCents int64, at time.Time) (LedgerEntry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return LedgerEntry{}, shared.NewValidationError("id", "ledger entry id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return LedgerEntry{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return LedgerEntry{}, shared.NewValidationError("endpoint", "endpoint is required")
	}
	if priceCents < 0 {
		return LedgerEntry{}, shared.NewValidationError("price_cents", "price must be non-negative")
	}
	return LedgerEntry{
		id:         id,
		tenantID:   tenantID,
		endpoint:   endpoint,
		priceCents: priceCents,
		reference:  strings.TrimSpace(reference),
		at:         at,
	}, nil
}

// ID returns the ledger entry identifier.
func (e LedgerEntry) ID() string { return e.id }

// TenantID returns the charged tenant.
func (e LedgerEntry) TenantID() string { return e.tenantID }

// Endpoint returns the billed endpoint.
func (e LedgerEntry) Endpoint() string { return e.endpoint }

// PriceCents returns the charged price in cents.
func (e LedgerEntry) PriceCents() int64 { return e.priceCents }

// Reference returns the triggering operation reference.
func (e LedgerEntry) Reference() string { return e.reference }

// At returns the time of the charge.
func (e LedgerEntry) At() time.Time { return e.at }
