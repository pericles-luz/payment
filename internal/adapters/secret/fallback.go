package secret

import (
	"context"
	"errors"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// FallbackStore is a read-only CredentialStore that resolves a (tenant, bank)
// credential from a PRIMARY store first and only consults a SECONDARY store when the
// primary has no record. It is the operator-tool analog of the api's env-as-bootstrap /
// durable-as-source-of-truth wiring (SIN-69366): register-webhook (SIN-69561 / F3) uses
// the durable CredentialVault as primary and the env-loaded secret.Store as secondary,
// so a self-serve client whose OAuth credential and PIX creditor key live ONLY in the
// durable vault (migration 0012) resolves exactly like a bootstrap tenant configured via
// PAYMENT_BANK_CREDS — the command sees both.
//
// The union is naturally deduplicated by tenant/bank because GetBankCredential is an
// exact-match keyed lookup: a tenant present in the primary is answered from the primary
// and the secondary is never consulted for it, so an env bootstrap value can never
// shadow a runtime-configured one.
//
// SECURITY: it adds NO logging and never widens the lookup — each backing store keeps its
// own deny-by-default, no-cross-tenant guarantee (ADR-0007 T1/T2). Only a genuine "not
// found" (shared.ErrNotFound) from the primary falls through to the secondary; any other
// primary error (an infrastructure fault, e.g. a decrypt failure) is surfaced unchanged
// so the caller fails CLOSED rather than silently reading a stale env value.
type FallbackStore struct {
	primary   ports.CredentialStore
	secondary ports.CredentialStore
}

// NewFallbackStore composes a primary over a secondary credential store. Either may be
// nil: a nil primary makes the store delegate straight to the secondary (the plain
// env-only path when no vault is configured), and a nil secondary means a primary miss
// stays a miss. With both nil, every lookup is ErrNotFound.
func NewFallbackStore(primary, secondary ports.CredentialStore) *FallbackStore {
	return &FallbackStore{primary: primary, secondary: secondary}
}

// Compile-time check that the composite satisfies the read port.
var _ ports.CredentialStore = (*FallbackStore)(nil)

// GetBankCredential returns the primary's credential for the exact (tenantID, bankID)
// pair, falling back to the secondary ONLY when the primary reports the pair absent
// (shared.ErrNotFound). A non-ErrNotFound primary error is returned as-is (fail closed).
// When the primary is nil the secondary is consulted directly; when the secondary is nil
// a miss returns shared.ErrNotFound.
func (f *FallbackStore) GetBankCredential(ctx context.Context, tenantID, bankID string) (ports.BankCredential, error) {
	if f.primary != nil {
		cred, err := f.primary.GetBankCredential(ctx, tenantID, bankID)
		if err == nil {
			return cred, nil
		}
		if !errors.Is(err, shared.ErrNotFound) {
			return ports.BankCredential{}, err
		}
	}
	if f.secondary == nil {
		return ports.BankCredential{}, shared.ErrNotFound
	}
	return f.secondary.GetBankCredential(ctx, tenantID, bankID)
}
