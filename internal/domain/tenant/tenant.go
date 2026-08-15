// Package tenant holds the Tenant aggregate. A tenant is an isolated customer
// (B2B) whose data must never leak across the tenant boundary. Pure domain.
package tenant

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Tenant is the aggregate root for an isolated customer account (empresa-cliente
// in the two-level tenancy model, ADR-0009).
type Tenant struct {
	id        string
	name      string
	active    bool
	createdAt time.Time
	// accountID is the owning Account (API user / reseller) in the two-level
	// tenancy model (ADR-0009). It is IMMUTABLE once assigned: a tenant belongs
	// to exactly one account and may never be re-parented (no attribution/billing
	// drift). An empty accountID means "self-account" — the NULL-safe legacy
	// semantics during the backfill window (migration 0007): a flat legacy tenant
	// is simply an account of one tenant, 1:1. AssignAccount performs the
	// one-time binding.
	accountID string
}

// New constructs a Tenant, enforcing its invariants. A tenant is created active
// with an empty (self) account — the dark-ship default that preserves the flat
// legacy behaviour until an account is assigned (ADR-0009 §4).
func New(id, name string, now time.Time) (*Tenant, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, shared.NewValidationError("id", "tenant id is required")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, shared.NewValidationError("name", "tenant name is required")
	}
	if len(name) > 200 {
		return nil, shared.NewValidationError("name", "tenant name too long")
	}
	return &Tenant{id: id, name: name, active: true, createdAt: now}, nil
}

// Rehydrate rebuilds a Tenant from persisted state without re-running creation
// validation (used by persistence adapters). The rehydrated tenant has an empty
// (self) account; use RehydrateWithAccount to carry a persisted owner.
func Rehydrate(id, name string, active bool, createdAt time.Time) *Tenant {
	return &Tenant{id: id, name: name, active: active, createdAt: createdAt}
}

// RehydrateWithAccount rebuilds a Tenant from persisted state including its owning
// account (which may be empty for a legacy self-account row). Additive companion
// to Rehydrate so persistence adapters can carry account_id without breaking the
// existing 4-arg constructor.
func RehydrateWithAccount(id, name string, active bool, createdAt time.Time, accountID string) *Tenant {
	return &Tenant{id: id, name: name, active: active, createdAt: createdAt, accountID: strings.TrimSpace(accountID)}
}

// ID returns the tenant identifier.
func (t *Tenant) ID() string { return t.id }

// Name returns the tenant display name.
func (t *Tenant) Name() string { return t.name }

// Active reports whether the tenant may transact.
func (t *Tenant) Active() bool { return t.active }

// CreatedAt returns the creation timestamp.
func (t *Tenant) CreatedAt() time.Time { return t.createdAt }

// AccountID returns the owning account, or "" for a self-account (legacy/flat)
// tenant that has not yet been bound to a real account (ADR-0009 §4 NULL-safe
// semantics).
func (t *Tenant) AccountID() string { return t.accountID }

// AssignAccount binds this tenant to its owning account exactly once. The binding
// is IMMUTABLE (ADR-0009 §3.2): assigning is only allowed while the tenant is a
// self-account (empty accountID). Re-assigning the SAME account is an idempotent
// no-op (safe to retry the backfill); attempting to re-parent to a DIFFERENT
// account is rejected — this is the invariant that prevents billing/attribution
// drift. A blank id is rejected.
func (t *Tenant) AssignAccount(accountID string) error {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return shared.NewValidationError("account_id", "account id is required")
	}
	if t.accountID != "" && t.accountID != accountID {
		return shared.NewValidationError("account_id", "tenant account is immutable; re-parenting is not allowed")
	}
	t.accountID = accountID
	return nil
}

// Rename changes the tenant display name, enforcing the SAME invariants as New
// (non-blank, ≤ 200 chars, trimmed) so a persisted rename can never bypass the
// creation rules (ADR-0012 §1). It mutates only the name; id, active state,
// createdAt and the immutable accountID binding are untouched. A blank or
// over-long name is rejected as a validation error and leaves the tenant unchanged.
func (t *Tenant) Rename(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return shared.NewValidationError("name", "tenant name is required")
	}
	if len(name) > 200 {
		return shared.NewValidationError("name", "tenant name too long")
	}
	t.name = name
	return nil
}

// Deactivate suspends the tenant (no further transactions allowed).
func (t *Tenant) Deactivate() { t.active = false }

// Activate re-enables a suspended tenant so it may transact again. It is the
// inverse of Deactivate and is idempotent (activating an active tenant is a
// no-op), making the admin-plane activate/suspend toggle safe to retry.
func (t *Tenant) Activate() { t.active = true }
