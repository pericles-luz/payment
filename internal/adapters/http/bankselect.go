package http

import (
	"context"
	"net/http"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/platform/bankctx"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// BankResolver resolves which bank a tenant request routes to and validates that
// choice at the boundary (multi-bank selector, SIN-66022). It is the confused-deputy
// guard (OWASP A01): the tenant is ALWAYS the authenticated tenant (never client
// input), and an explicitly-selected bank must be both wired (have an adapter) AND
// configured for that tenant (have a credential) — otherwise the request is rejected
// with the SAME not-found error as any unknown resource, leaking no signal about
// which banks exist or which the tenant uses (deny-by-default, no oracle). It never
// falls back to a different bank than the one selected.
type BankResolver struct {
	// wired is the closed allow-list of bank slugs with a registered adapter
	// (registry.Banks()). Membership here is necessary but not sufficient — a tenant
	// must also hold a credential for the bank.
	wired map[string]struct{}
	creds ports.CredentialStore
}

// NewBankResolver builds a resolver over the wired bank slugs and the credential
// store. Slugs are normalized so the allow-list and the request selector compare on
// the same canonical form.
func NewBankResolver(wired []string, creds ports.CredentialStore) *BankResolver {
	set := make(map[string]struct{}, len(wired))
	for _, id := range wired {
		if norm, ok := normalizeBankID(id); ok {
			set[norm] = struct{}{}
		}
	}
	return &BankResolver{wired: set, creds: creds}
}

// Resolve returns the bank id a request routes to. requested is the raw selector
// (header X-Bank-Id or the DTO `bank` field), possibly empty.
//
//   - Empty selector (legacy / single-bank clients): the retro-compatible default —
//     if the tenant has exactly ONE configured wired bank, use it; otherwise
//     ports.BankIDC6. This path never rejects, preserving 100% of pre-multi-bank
//     behaviour.
//   - Explicit selector: it MUST normalize cleanly (no control chars), be wired, and
//     be configured for the authenticated tenant. Any failure returns
//     shared.ErrNotFound — indistinguishable from a genuine not-found, so a caller
//     cannot enumerate banks or probe another tenant's configuration. The selected
//     bank is never silently swapped for another (no confused-deputy).
func (b *BankResolver) Resolve(ctx context.Context, tenantID, requested string) (string, error) {
	if strings.TrimSpace(requested) == "" {
		return b.defaultBank(ctx, tenantID), nil
	}
	id, ok := normalizeBankID(requested)
	if !ok {
		return "", shared.ErrNotFound
	}
	if _, wired := b.wired[id]; !wired {
		return "", shared.ErrNotFound
	}
	if _, err := b.creds.GetBankCredential(ctx, tenantID, id); err != nil {
		// Not configured for this tenant (or any store error) → same not-found, no
		// oracle. Never fall back to another bank.
		return "", shared.ErrNotFound
	}
	return id, nil
}

// defaultBank implements the retro-compatible default for an absent selector: the
// tenant's single configured wired bank, else ports.BankIDC6. The tenant is the
// authenticated tenant, so this only ever resolves to a bank the tenant itself holds
// (or the safe default), never to another tenant's bank.
func (b *BankResolver) defaultBank(ctx context.Context, tenantID string) string {
	configured := ""
	count := 0
	for id := range b.wired {
		if _, err := b.creds.GetBankCredential(ctx, tenantID, id); err == nil {
			configured = id
			count++
		}
	}
	if count == 1 {
		return configured
	}
	return ports.BankIDC6
}

// normalizeBankID canonicalises a bank slug (lowercase + trimmed) and fails closed
// on a slug carrying NUL or any other control char (< 0x20 or 0x7f). The credential
// store keys credentials by tenant + "\x00" + bank, so a NUL-bearing slug could
// otherwise forge/collide a composite key once the slug is request-influenced
// (SIN-66022 / SIN-66040 hardening). An empty result is reported as not-ok so the
// caller treats it as the default-selector path, never as a valid explicit slug.
//
// It delegates to ports.CanonicalBankID — the single shared canonicaliser the
// provider Registry also uses on its key boundary (SIN-66056) — so the request
// selector and the registry key can never diverge.
func normalizeBankID(bankID string) (string, bool) {
	return ports.CanonicalBankID(bankID)
}

// bankRouteMiddleware resolves the bank for every tenant request from the X-Bank-Id
// header (empty ⇒ retro-compatible default) and stamps it on the context for the
// output-port routers to dispatch on. A rejected explicit header (unknown/unconfigured
// bank) short-circuits with the uniform not-found error. It MUST sit after the tenant
// authenticator so the authenticated tenant is already on the context.
func bankRouteMiddleware(resolver *BankResolver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := tenantFromContext(r.Context())
			bankID, err := resolver.Resolve(r.Context(), tenantID, r.Header.Get("X-Bank-Id"))
			if err != nil {
				writeDomainError(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(bankctx.WithBankID(r.Context(), bankID)))
		})
	}
}

// rebindBank re-resolves the routed bank from a request-body `bank` field, which
// overrides the header-resolved bank (the body field is the canonical write-path
// selector, ADR-0007). An empty field leaves the header/default resolution in place.
// On rejection it writes the uniform not-found error and returns ok=false so the
// caller aborts. On success it returns a request carrying the updated bank context.
func (s *Server) rebindBank(w http.ResponseWriter, r *http.Request, bodyBank string) (*http.Request, bool) {
	if strings.TrimSpace(bodyBank) == "" {
		return r, true
	}
	if s.bankResolver == nil {
		return r, true
	}
	bankID, err := s.bankResolver.Resolve(r.Context(), tenantFromContext(r.Context()), bodyBank)
	if err != nil {
		writeDomainError(w, err)
		return r, false
	}
	return r.WithContext(bankctx.WithBankID(r.Context(), bankID)), true
}
