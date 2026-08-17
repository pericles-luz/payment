package inmemory

import (
	"context"
	"sync"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundwebhook"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// OutboundWebhookStore is the in-process implementation of the per-Conta outbound
// webhook config store (app.OutboundWebhookStore, SIN-69490), used in stub/dev wiring
// and tests exactly like the other in-memory stores. The durable sqlite
// OutboundWebhookVault satisfies the SAME port with identical behaviour (get/upsert/
// delete keyed by account id, one config per Conta).
//
// It stores the aggregate by value (a copy) so a caller mutating the returned pointer
// cannot silently alter the stored config without an explicit Upsert — matching the
// round-trip semantics of the sqlite adapter, which rehydrates a fresh aggregate on
// every Get. The signing secret is held in memory only (this adapter is not "at rest";
// production uses the encrypted sqlite vault), so no sealing happens here.
type OutboundWebhookStore struct {
	mu     sync.RWMutex
	byAcct map[string]storedWebhook
}

// storedWebhook is the flat, immutable snapshot of a Config the map holds, so Get can
// rebuild a fresh aggregate (no shared pointer) exactly like the sqlite Rehydrate path.
type storedWebhook struct {
	url           string
	signingSecret string
	enabled       bool
	createdAt     time.Time
	updatedAt     time.Time
}

// NewOutboundWebhookStore builds an empty store.
func NewOutboundWebhookStore() *OutboundWebhookStore {
	return &OutboundWebhookStore{byAcct: make(map[string]storedWebhook)}
}

// GetOutboundWebhook returns the Conta's config, or shared.ErrNotFound when none is
// configured. It rehydrates a fresh aggregate from the stored snapshot so the caller
// never holds a pointer into the map (matching the sqlite adapter).
func (s *OutboundWebhookStore) GetOutboundWebhook(_ context.Context, accountID string) (*outboundwebhook.Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.byAcct[accountID]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return outboundwebhook.Rehydrate(accountID, rec.url, rec.signingSecret, rec.enabled, rec.createdAt, rec.updatedAt), nil
}

// UpsertOutboundWebhook persists (create or update) a Conta's config, keyed by
// account id. It snapshots the aggregate's fields, so a later mutation of the passed
// pointer does not leak into the store.
func (s *OutboundWebhookStore) UpsertOutboundWebhook(_ context.Context, cfg *outboundwebhook.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byAcct[cfg.AccountID()] = storedWebhook{
		url:           cfg.URL(),
		signingSecret: cfg.SigningSecret(),
		enabled:       cfg.Enabled(),
		createdAt:     cfg.CreatedAt(),
		updatedAt:     cfg.UpdatedAt(),
	}
	return nil
}

// DeleteOutboundWebhook hard-deletes a Conta's config. It is IDEMPOTENT — deleting an
// absent config is a no-op that still returns nil.
func (s *OutboundWebhookStore) DeleteOutboundWebhook(_ context.Context, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byAcct, accountID)
	return nil
}
