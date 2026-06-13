// Package secret provides a CredentialStore adapter. Bank credentials are
// isolated per tenant and never live in code. The store is loaded from
// configuration/environment (a vault adapter is a drop-in replacement). Secrets
// are returned only transiently and must never be logged (threat C1/C4).
package secret

import (
	"context"
	"sync"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Store is an in-process CredentialStore keyed by tenant. The concrete secret
// values are injected at construction from config/env — not hard-coded.
type Store struct {
	mu    sync.RWMutex
	creds map[string]ports.BankCredential
}

// NewStore builds a Store from a tenant→credential map (typically loaded from
// environment/secret manager at startup).
func NewStore(creds map[string]ports.BankCredential) *Store {
	cp := make(map[string]ports.BankCredential, len(creds))
	for k, v := range creds {
		cp[k] = v
	}
	return &Store{creds: cp}
}

// GetBankCredential returns the credential for a tenant, scoped strictly by the
// authenticated tenant id (threat C4). Returns ErrNotFound if absent.
func (s *Store) GetBankCredential(ctx context.Context, tenantID string) (ports.BankCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.creds[tenantID]
	if !ok {
		return ports.BankCredential{}, shared.ErrNotFound
	}
	return c, nil
}

// Set stores/replaces a tenant credential (used by the admin plane / config reload).
func (s *Store) Set(tenantID string, c ports.BankCredential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.TenantID = tenantID
	s.creds[tenantID] = c
}

// SetBankCredential implements ports.CredentialWriter: it persists a tenant's
// bank credential. The secret is held only in the store and never returned,
// logged or echoed (threat C1/C4). Empty inputs are rejected as a validation
// error without including the secret value in the message.
func (s *Store) SetBankCredential(_ context.Context, tenantID, clientID, secret string) error {
	if tenantID == "" {
		return shared.NewValidationError("tenant_id", "is required")
	}
	if clientID == "" {
		return shared.NewValidationError("client_id", "is required")
	}
	if secret == "" {
		return shared.NewValidationError("secret", "is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[tenantID] = ports.BankCredential{TenantID: tenantID, ClientID: clientID, Secret: secret}
	return nil
}
