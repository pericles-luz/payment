// Package account holds the Account aggregate — the API user / reseller that
// sits ABOVE the tenant in the two-level tenancy model (ADR-0009, SIN-69119 §3.1).
//
// An Account owns N Tenants (empresas-clientes) by reference (id), not by
// composition — the two aggregates stay separate (DDD-lite; the self-join on
// tenants was rejected, see ADR-0009 §4). An Account is an attribution-only
// concept: it identifies who a token belongs to and is the rollup target for
// billing, but it NEVER holds a bank credential and NEVER touches money (model
// (a) PSP-Indireto pass-through). It mirrors the Tenant aggregate deliberately so
// the persistence keying and the admin plane can reuse the tenant schema shape.
//
// Pure domain: no database/sql, no HTTP, no vendor SDK.
package account

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Account is the aggregate root for an API user (reseller) that owns tenants.
type Account struct {
	id        string
	name      string
	active    bool
	createdAt time.Time
}

// New constructs an Account, enforcing its invariants. An account is created
// active. Invariants mirror Tenant.New so the admin plane treats the two the
// same way.
func New(id, name string, now time.Time) (*Account, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, shared.NewValidationError("id", "account id is required")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, shared.NewValidationError("name", "account name is required")
	}
	if len(name) > 200 {
		return nil, shared.NewValidationError("name", "account name too long")
	}
	return &Account{id: id, name: name, active: true, createdAt: now}, nil
}

// Rehydrate rebuilds an Account from persisted state without re-running creation
// validation (used by persistence adapters).
func Rehydrate(id, name string, active bool, createdAt time.Time) *Account {
	return &Account{id: id, name: name, active: active, createdAt: createdAt}
}

// selfAccountPrefix is the deterministic prefix that derives a tenant's
// self-account id. It MUST match the backfill in migration 0007
// ('acct-' || tenant.id) so the flat legacy model is "an account of one tenant,
// 1:1" with a reproducible id and no bookkeeping (ADR-0009 §4).
const selfAccountPrefix = "acct-"

// SelfAccountID returns the id of the self-account that owns a legacy/flat tenant
// — the single home for the "acct-<tenantID>" convention established by migration
// 0007's backfill (ADR-0009 §4). A tenant whose owning account has not been
// explicitly assigned (empty accountID, NULL-safe legacy semantics) belongs to
// this derived self-account. Auth (SIN-69126) and metering (SIN-69127) both
// resolve the account through here so the derivation lives in exactly one place.
// A blank tenant id yields "" (there is no self-account for a non-tenant).
func SelfAccountID(tenantID string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ""
	}
	return selfAccountPrefix + tenantID
}

// IsSelfAccountID reports whether id is a derived self-account id (the
// "acct-<tenantID>" convention from migration 0007's backfill, ADR-0009 §4). The
// admin console uses it to distinguish an implicit legacy self-account (one
// empresa-cliente, 1:1) from a real reseller account created explicitly — so the
// Contas list can hide the per-tenant self-accounts by default (§6). Classifying
// by the same prefix constant SelfAccountID emits keeps the derivation in one
// place. A real account minted from an opaque id provider never carries the prefix.
func IsSelfAccountID(id string) bool {
	return strings.HasPrefix(strings.TrimSpace(id), selfAccountPrefix)
}

// ID returns the account identifier.
func (a *Account) ID() string { return a.id }

// Name returns the account display name.
func (a *Account) Name() string { return a.name }

// Active reports whether the account is enabled.
func (a *Account) Active() bool { return a.active }

// CreatedAt returns the creation timestamp.
func (a *Account) CreatedAt() time.Time { return a.createdAt }

// Deactivate suspends the account.
func (a *Account) Deactivate() { a.active = false }

// Activate re-enables a suspended account. Idempotent, mirroring Tenant.Activate.
func (a *Account) Activate() { a.active = true }
