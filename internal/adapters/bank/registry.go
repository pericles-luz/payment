package bank

import (
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// ProviderSet is the full set of bank/PSP output-port instances for ONE bank. Each
// instance is already bound to its own bank identity (it reads the (tenant, bankID)
// credential for its fixed bankID), so the port methods stay (ctx, tenantID, …) and
// never carry the bank on a business request (ADR-0007 §3, SIN-66022). A field may
// be nil when a wired bank does not implement that surface; the router then fails
// closed with shared.ErrUnavailable rather than routing to a different bank.
type ProviderSet struct {
	Bank         ports.BankProvider
	Pix          ports.PixProvider
	PixDueCharge ports.PixDueChargeProvider
	Checkout     ports.CheckoutProvider
	Boleto       ports.BoletoProvider
	DDA          ports.DDAProvider
	Statement    ports.StatementProvider
	// CredInvalidator evicts cached state keyed on this bank's credential (the C6
	// OAuth2 token cache) after a credential write. Nil when the bank caches nothing
	// (the in-memory stub). Aggregated across banks by the composite invalidator.
	CredInvalidator ports.CredentialInvalidator
}

// Registry maps a non-secret bank slug to its ProviderSet. It is the closed set of
// banks the platform has a wired adapter for: a request may only ever route to a
// bank in this set (deny-by-default — the HTTP selector rejects any other slug with
// the uniform not-found error, never a fallback to another bank). It is built once
// at startup and is read-only thereafter, so it needs no locking.
type Registry struct {
	sets map[string]ProviderSet
}

// NewRegistry builds an empty Registry.
func NewRegistry() *Registry {
	return &Registry{sets: make(map[string]ProviderSet)}
}

// Register adds (or replaces) the ProviderSet wired for bankID. Called only during
// startup wiring. The slug MUST already be in canonical form — exactly what
// ports.CanonicalBankID returns: lowercase, trimmed, non-empty, no NUL or other
// control char. A non-canonical slug (uppercase, surrounding space, empty, or a
// control char) is REJECTED with an error rather than silently fixed or inserted as
// a poisoned key. Today every registered slug is a canonical lowercase constant
// (ports.BankIDC6), so this is secure-by-default defense-in-depth (SIN-66056): the
// write boundary refuses non-canonical input outright, so the registry key space can
// never hold a slug that the canonicalised Get/Has lookups would fail to match (or,
// worse, a NUL-bearing key that could collide a composite credential key).
func (r *Registry) Register(bankID string, set ProviderSet) error {
	id, ok := ports.CanonicalBankID(bankID)
	if !ok || id != bankID {
		return fmt.Errorf("bank registry: refusing to register non-canonical bank slug %q (canonical form is %q)", bankID, id)
	}
	r.sets[id] = set
	return nil
}

// Get returns the ProviderSet wired for bankID and whether one exists. A false
// second result means the bank has no wired adapter — the caller MUST fail closed.
// The lookup key is canonicalised the same way Register canonicalises it, so a bank
// resolves only by its canonical form and a non-canonical slug (empty / control char)
// is reported as not-found rather than ever matching a key.
func (r *Registry) Get(bankID string) (ProviderSet, bool) {
	id, ok := ports.CanonicalBankID(bankID)
	if !ok {
		return ProviderSet{}, false
	}
	s, ok := r.sets[id]
	return s, ok
}

// Has reports whether bankID names a wired bank. It is the allow-list the HTTP
// selector validates an explicit bank selector against (a requested bank that is
// not wired is rejected with the uniform not-found error — no existence oracle). It
// canonicalises the slug like Get, so membership is decided on the canonical form.
func (r *Registry) Has(bankID string) bool {
	id, ok := ports.CanonicalBankID(bankID)
	if !ok {
		return false
	}
	_, ok = r.sets[id]
	return ok
}

// Banks returns the wired bank slugs. The order is unspecified (map iteration); the
// selector only needs membership and a count, never an order.
func (r *Registry) Banks() []string {
	out := make([]string, 0, len(r.sets))
	for id := range r.sets {
		out = append(out, id)
	}
	return out
}

// CredentialInvalidator returns a ports.CredentialInvalidator that fans a tenant's
// token-cache eviction out to EVERY wired bank that caches credential state. A
// credential write for one bank cannot know which adapters cache a token for the
// tenant, and evicting a bank that holds nothing is a safe no-op, so the broad fan
// out closes the token-revocation lag without leaking which banks the tenant uses
// (ADR-0003 / ADR-0007). Returns nil when no wired bank caches anything, so the
// admin services fall back to their no-op evictor unchanged.
func (r *Registry) CredentialInvalidator() ports.CredentialInvalidator {
	inv := make([]ports.CredentialInvalidator, 0, len(r.sets))
	for _, s := range r.sets {
		if s.CredInvalidator != nil {
			inv = append(inv, s.CredInvalidator)
		}
	}
	if len(inv) == 0 {
		return nil
	}
	return compositeInvalidator(inv)
}

// compositeInvalidator invalidates a tenant's cached credential state across every
// wired bank that caches anything.
type compositeInvalidator []ports.CredentialInvalidator

func (c compositeInvalidator) InvalidateToken(tenantID string) {
	for _, inv := range c {
		inv.InvalidateToken(tenantID)
	}
}
