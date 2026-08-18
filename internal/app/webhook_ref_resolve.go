package app

import (
	"context"

	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// RefSource records where a webhook ref's effective tenant binding came from, so the
// operator tool (cmd/register-webhook, SIN-69561 / F3) can report the resolution without
// ever printing the ref itself.
type RefSource int

const (
	// RefSourceNone means the ref resolved to no tenant: the durable store has no record
	// and no env-declared tenant was supplied. The caller reports this as an unregistered
	// ref and takes NO side effect (fail closed).
	RefSourceNone RefSource = iota
	// RefSourceDurable means the tenant came from the durable WebhookRefStore (F1) — the
	// authoritative binding recorded at mint time.
	RefSourceDurable
	// RefSourceEnv means the tenant came from the env-declared PAYMENT_WEBHOOK_REFS entry
	// (bootstrap), because the durable store had no record of the ref (or is not wired).
	RefSourceEnv
)

// RefResolution is the outcome of resolving one plaintext ref to its owning tenant.
// It carries NO plaintext ref or URL — only the resolved tenant id (a non-secret) and
// provenance flags — so a caller can log it safely.
type RefResolution struct {
	// TenantID is the effective owner, or "" when Source is RefSourceNone.
	TenantID string
	// Source is where TenantID came from.
	Source RefSource
	// Mismatch is true when the durable store bound the ref to a DIFFERENT tenant than the
	// env-declared mapping. The durable binding wins (it is the source of truth), but the
	// caller SHOULD surface the conflict as a masked warning — an env mapping that
	// disagrees with the store is a misconfiguration, not a routing instruction.
	Mismatch bool
}

// WebhookRefResolver binds an operator-supplied plaintext webhook ref to the tenant the
// durable WebhookRefStore recorded at mint time (SIN-69559 / F1), falling back to the
// env-declared tenant when the store has no record. It exists so cmd/register-webhook
// (F3) can see self-serve clients — whose ref was minted into the durable store — without
// trusting the env mapping blindly.
//
// SECURITY: the plaintext ref is a bearer capability. It is hashed with webhookref.Sum
// before it reaches the store and is never logged, returned, or compared in the clear;
// only its SHA-256 crosses the port. A structurally invalid ref is rejected BEFORE any
// lookup so a malformed/percent-encoded input can never reach the credential store.
type WebhookRefResolver struct {
	store ports.WebhookRefStore
}

// NewWebhookRefResolver wraps a durable ref store. A nil store yields a resolver that
// always falls back to the env-declared tenant (the plain bootstrap path when no durable
// store is wired), so the command keeps working env-only.
func NewWebhookRefResolver(store ports.WebhookRefStore) *WebhookRefResolver {
	return &WebhookRefResolver{store: store}
}

// Resolve returns the effective tenant for a plaintext ref given its env-declared tenant
// (which may be "").
//
//   - No durable store wired: returns the env tenant (RefSourceEnv), or RefSourceNone when
//     the env tenant is empty.
//   - Structurally invalid ref: never looked up; resolves to the env tenant only (a
//     malformed ref cannot be a durable capability), or RefSourceNone.
//   - Durable store has the ref: returns the store's tenant (RefSourceDurable), flagging a
//     Mismatch when a non-empty env tenant disagrees.
//   - Durable store misses (no such ref): falls back to the env tenant (RefSourceEnv), or
//     RefSourceNone when empty.
//   - Durable store errors: returns the error (fail closed) — the caller must NOT register
//     against a possibly-wrong binding.
func (r *WebhookRefResolver) Resolve(ctx context.Context, ref, envTenant string) (RefResolution, error) {
	if r == nil || r.store == nil || !webhookref.Valid(ref) {
		return envOnly(envTenant), nil
	}
	sum := webhookref.Sum(ref)
	durable, ok, err := r.store.LookupWebhookRef(ctx, sum[:])
	if err != nil {
		return RefResolution{}, err
	}
	if !ok {
		return envOnly(envTenant), nil
	}
	return RefResolution{
		TenantID: durable,
		Source:   RefSourceDurable,
		Mismatch: envTenant != "" && envTenant != durable,
	}, nil
}

// envOnly builds the resolution for the env-declared tenant with no durable binding.
func envOnly(envTenant string) RefResolution {
	if envTenant == "" {
		return RefResolution{Source: RefSourceNone}
	}
	return RefResolution{TenantID: envTenant, Source: RefSourceEnv}
}
