package inmemory

import (
	"context"
	"encoding/hex"
	"sync"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// WebhookRefStore is the in-process implementation of ports.WebhookRefStore
// (SIN-69559 / F1), used in stub/dev wiring and tests exactly like the other in-memory
// stores. The durable sqlite WebhookRefStore satisfies the SAME port with identical
// behaviour (put/lookup keyed by the ref's SHA-256).
//
// SECURITY: like the durable adapter and the bootstrap map, it holds only the ref's
// hash — the plaintext ref never enters the store. The map key is the hex SHA-256 so
// two []byte hashes with the same contents collide correctly.
type WebhookRefStore struct {
	mu     sync.RWMutex
	byHash map[string]string // hex(sha256(ref)) -> tenantID
}

// NewWebhookRefStore builds an empty store.
func NewWebhookRefStore() *WebhookRefStore {
	return &WebhookRefStore{byHash: make(map[string]string)}
}

// Compile-time check that the adapter satisfies the port.
var _ ports.WebhookRefStore = (*WebhookRefStore)(nil)

// PutWebhookRef binds a minted ref (by its SHA-256) to tenantID. Re-putting the same
// hash overwrites with the same tenant (idempotent); an empty hash or tenant is a
// validation error, mirroring the durable adapter.
func (s *WebhookRefStore) PutWebhookRef(_ context.Context, refSHA []byte, tenantID string) error {
	if len(refSHA) == 0 {
		return shared.NewValidationError("ref_sha256", "ref hash is required")
	}
	if tenantID == "" {
		return shared.NewValidationError("tenant_id", "tenant id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byHash[hex.EncodeToString(refSHA)] = tenantID
	return nil
}

// LookupWebhookRef resolves a ref's SHA-256 to its owning tenant id. An unknown ref
// returns ("", false, nil) — the same non-oracle miss as the durable adapter. This
// in-memory adapter never returns a non-nil error (it has no infrastructure to fault).
func (s *WebhookRefStore) LookupWebhookRef(_ context.Context, refSHA []byte) (string, bool, error) {
	if len(refSHA) == 0 {
		return "", false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tenantID, ok := s.byHash[hex.EncodeToString(refSHA)]
	return tenantID, ok, nil
}
