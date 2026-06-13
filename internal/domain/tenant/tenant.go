// Package tenant holds the Tenant aggregate. A tenant is an isolated customer
// (B2B) whose data must never leak across the tenant boundary. Pure domain.
package tenant

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Tenant is the aggregate root for an isolated customer account.
type Tenant struct {
	id        string
	name      string
	active    bool
	createdAt time.Time
}

// New constructs a Tenant, enforcing its invariants. A tenant is created active.
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
// validation (used by persistence adapters).
func Rehydrate(id, name string, active bool, createdAt time.Time) *Tenant {
	return &Tenant{id: id, name: name, active: active, createdAt: createdAt}
}

// ID returns the tenant identifier.
func (t *Tenant) ID() string { return t.id }

// Name returns the tenant display name.
func (t *Tenant) Name() string { return t.name }

// Active reports whether the tenant may transact.
func (t *Tenant) Active() bool { return t.active }

// CreatedAt returns the creation timestamp.
func (t *Tenant) CreatedAt() time.Time { return t.createdAt }

// Deactivate suspends the tenant (no further transactions allowed).
func (t *Tenant) Deactivate() { t.active = false }

// Activate re-enables a suspended tenant so it may transact again. It is the
// inverse of Deactivate and is idempotent (activating an active tenant is a
// no-op), making the admin-plane activate/suspend toggle safe to retry.
func (t *Tenant) Activate() { t.active = true }
