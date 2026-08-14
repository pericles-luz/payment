// Package invoice holds the Fatura (invoice) domain: the durable, append-only,
// auditable statement of what an empresa-cliente (tenant) owes for its metered
// API consumption over a closed billing period.
//
// An Invoice is a FROZEN SNAPSHOT of the append-only billing ledger for one
// tenant over a half-open window [PeriodStart, PeriodEnd). It is built once, at
// generation time, from the ledger entries that fall inside the window — its line
// totals are the sum of recorded LedgerEntry prices, never a value recomputed
// from the mutable endpoint_pricing table. This is what makes the invoice
// authoritative and reproducible: the same window over the same ledger always
// yields the same figures, and a later price change never rewrites a past
// invoice. (Mirrors the "ledger is authoritative for billing" invariant of
// billing.LedgerEntry and the ConsumptionReport it aggregates.)
//
// An Invoice is IMMUTABLE by construction: fields are unexported and there is no
// mutator, so once generated an invoice never changes. The storage adapters only
// ever INSERT (append-only) — regenerating a period produces a NEW timestamped
// invoice, it never overwrites an existing one, so the full billing history is
// preserved (the forensic property OWASP A09 relies on).
//
// PII: an invoice carries only tenant/account ids, endpoint names, call counts
// and money — no personal data — so, unlike termsconsent.Record, it needs no
// LogValue redaction.
//
// Pure domain: this package MUST NOT import database/sql, net/http, vendor SDKs
// or the ports package. Persistence lives behind an app-level InvoiceStore port,
// implemented by the sqlite and inmemory adapters.
package invoice

import (
	"sort"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// LineItem is one endpoint's aggregated charge on an invoice: how many billable
// calls of that endpoint occurred in the period and their summed price in cents.
// The subtotal is the sum of the recorded ledger-entry prices (authoritative),
// not calls × a current unit price — a price change mid-period is already baked
// into each entry, so the invoice reflects what was actually charged.
type LineItem struct {
	endpoint      string
	calls         int
	subtotalCents int64
}

// NewLineItem builds a validated invoice line: a non-empty endpoint, a positive
// call count and a non-negative subtotal (a free endpoint bills zero cents).
func NewLineItem(endpoint string, calls int, subtotalCents int64) (LineItem, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return LineItem{}, shared.NewValidationError("endpoint", "endpoint is required")
	}
	if calls <= 0 {
		return LineItem{}, shared.NewValidationError("calls", "calls must be positive")
	}
	if subtotalCents < 0 {
		return LineItem{}, shared.NewValidationError("subtotal_cents", "subtotal must be non-negative")
	}
	return LineItem{endpoint: endpoint, calls: calls, subtotalCents: subtotalCents}, nil
}

// Endpoint returns the billed endpoint.
func (l LineItem) Endpoint() string { return l.endpoint }

// Calls returns the number of billable calls in the period.
func (l LineItem) Calls() int { return l.calls }

// SubtotalCents returns the line's summed price in cents.
func (l LineItem) SubtotalCents() int64 { return l.subtotalCents }

// Invoice is the immutable, append-only Fatura for one tenant over a closed
// billing period. It is constructed once (New) or rehydrated from storage
// (Rehydrate) and never mutated.
type Invoice struct {
	id          string
	tenantID    string
	accountID   string // rollup parent (API user / reseller); "" = self-account (legacy/flat)
	periodStart time.Time
	periodEnd   time.Time
	lines       []LineItem
	totalCalls  int
	totalCents  int64
	generatedAt time.Time
}

// New builds an invoice for tenant over the half-open window [periodStart,
// periodEnd), enforcing its invariants and DERIVING the totals from the lines so
// the header can never drift from the body. The lines are sorted by endpoint for
// a stable, reproducible document. accountID is the rollup parent and may be
// empty (a self-account tenant not yet bound to a real account).
//
// Invariants: non-empty id and tenantID; a bounded, non-empty, ordered window
// (periodStart strictly before periodEnd); and every line valid. An empty line
// set is allowed — a zero-consumption period is a legitimate R$ 0,00 invoice, so
// the reseller still has a per-period record.
func New(id, tenantID, accountID string, periodStart, periodEnd, generatedAt time.Time, lines []LineItem) (Invoice, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Invoice{}, shared.NewValidationError("id", "invoice id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Invoice{}, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	if periodStart.IsZero() || periodEnd.IsZero() {
		return Invoice{}, shared.NewValidationError("period", "period start and end are required")
	}
	if !periodStart.Before(periodEnd) {
		return Invoice{}, shared.NewValidationError("period", "period start must be before period end")
	}
	// Copy + sort so the caller's slice cannot alias the invoice's internal state
	// and the document order is deterministic (parity with ConsumptionReport).
	cp := make([]LineItem, len(lines))
	copy(cp, lines)
	sort.SliceStable(cp, func(i, j int) bool { return cp[i].endpoint < cp[j].endpoint })
	var totalCalls int
	var totalCents int64
	for _, l := range cp {
		if l.endpoint == "" {
			return Invoice{}, shared.NewValidationError("line", "invalid line item")
		}
		totalCalls += l.calls
		totalCents += l.subtotalCents
	}
	return Invoice{
		id:          id,
		tenantID:    tenantID,
		accountID:   strings.TrimSpace(accountID),
		periodStart: periodStart,
		periodEnd:   periodEnd,
		lines:       cp,
		totalCalls:  totalCalls,
		totalCents:  totalCents,
		generatedAt: generatedAt,
	}, nil
}

// Rehydrate rebuilds an Invoice from persisted state without re-running creation
// validation (used by persistence adapters). The stored totals are trusted as
// written by a prior New; the lines are copied so the caller cannot mutate the
// rehydrated aggregate.
func Rehydrate(id, tenantID, accountID string, periodStart, periodEnd, generatedAt time.Time, lines []LineItem, totalCalls int, totalCents int64) Invoice {
	cp := make([]LineItem, len(lines))
	copy(cp, lines)
	return Invoice{
		id:          id,
		tenantID:    tenantID,
		accountID:   accountID,
		periodStart: periodStart,
		periodEnd:   periodEnd,
		lines:       cp,
		totalCalls:  totalCalls,
		totalCents:  totalCents,
		generatedAt: generatedAt,
	}
}

// ID returns the invoice identifier.
func (inv Invoice) ID() string { return inv.id }

// TenantID returns the billed tenant (empresa-cliente).
func (inv Invoice) TenantID() string { return inv.tenantID }

// AccountID returns the rollup parent account, or "" for a self-account tenant.
func (inv Invoice) AccountID() string { return inv.accountID }

// PeriodStart returns the inclusive start of the billing window.
func (inv Invoice) PeriodStart() time.Time { return inv.periodStart }

// PeriodEnd returns the exclusive end of the billing window.
func (inv Invoice) PeriodEnd() time.Time { return inv.periodEnd }

// GeneratedAt returns when the invoice was generated (frozen).
func (inv Invoice) GeneratedAt() time.Time { return inv.generatedAt }

// TotalCalls returns the total billable calls across all lines.
func (inv Invoice) TotalCalls() int { return inv.totalCalls }

// TotalCents returns the invoice grand total in cents.
func (inv Invoice) TotalCents() int64 { return inv.totalCents }

// Lines returns a copy of the invoice's line items so the immutable aggregate
// cannot be mutated through the returned slice.
func (inv Invoice) Lines() []LineItem {
	out := make([]LineItem, len(inv.lines))
	copy(out, inv.lines)
	return out
}
