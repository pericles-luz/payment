package app

import (
	"context"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// WebhookRefMintService mints a durable per-tenant C6 webhook callback ref and
// persists ONLY its hash (SIN-69559 / F1). It is the bridge between the pure ref
// crypto (domain/webhookref) and the durable store (ports.WebhookRefStore): generate a
// 256-bit CSPRNG ref, persist its SHA-256 bound to the tenant, and return the plaintext
// to the caller EXACTLY once (display-once).
//
// SECURITY: the plaintext ref is a capability secret — it is returned to the caller and
// never logged, never re-persisted in the clear, and never derived from the tenant id
// (always fresh CSPRNG). Only the hash crosses the store port.
type WebhookRefMintService struct {
	store ports.WebhookRefStore
}

// NewWebhookRefMintService wires the mint service over a durable ref store. A nil store
// yields a service whose MintWebhookRef fails closed (it cannot persist), so callers
// that require durability get a clear error rather than a silent no-mint.
func NewWebhookRefMintService(store ports.WebhookRefStore) *WebhookRefMintService {
	return &WebhookRefMintService{store: store}
}

// MintWebhookRef generates a fresh ref for tenantID, persists its hash, and returns the
// plaintext once. It never returns the ref if persistence fails — a caller that gets an
// error must NOT surface a ref the store does not know about (which would authenticate
// nothing). The tenant must already exist (the store's FK enforces it).
func (s *WebhookRefMintService) MintWebhookRef(ctx context.Context, tenantID string) (string, error) {
	if s == nil || s.store == nil {
		return "", fmt.Errorf("webhook ref store not configured")
	}
	ref, err := webhookref.Generate()
	if err != nil {
		return "", fmt.Errorf("generate webhook ref: %w", err)
	}
	sum := webhookref.Sum(ref)
	if err := s.store.PutWebhookRef(ctx, sum[:], tenantID); err != nil {
		return "", fmt.Errorf("persist webhook ref: %w", err)
	}
	return ref, nil
}
