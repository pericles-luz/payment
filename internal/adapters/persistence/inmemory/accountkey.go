package inmemory

import (
	"context"
	"sync"

	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// AccountKeyStore is the in-process implementation of ports.AccountKeyStore — the
// first adapter for the account-key credential (ADR-0011 §3, SIN-69278/B1), used in
// stub/dev wiring and tests exactly like the other in-memory stores. The durable
// sqlite adapter satisfies the SAME port with identical behaviour.
//
// Only the hash is ever held: the domain (accountkey.New) hashes the plaintext at
// construction, so a plaintext secret never lands in this map. Authentication is an
// O(1) lookup keyed by the secret's hash (mirroring StaticTokenAuth's webhook-ref
// map), never a plaintext comparison — so there is no per-entry timing oracle.
//
// Exactly one active key exists per account: PutKey/Rotate supersede the previous
// key (removing its hash index) before inserting the new one, so a rotated secret
// stops authenticating immediately (ADR-0011 §3, invalidate-immediately default).
type AccountKeyStore struct {
	mu sync.RWMutex
	// byAccount holds the current active key per account id. Rotation replaces the
	// value; there is never more than one active key per account.
	byAccount map[string]*accountkey.AccountKey
	// byHash maps a live key's hash-at-rest to its account id, for O(1) authenticate.
	// It holds ONLY active hashes: a superseded key's hash is deleted on rotation.
	byHash map[string]string
	clock  ports.Clock
}

// NewAccountKeyStore builds an empty store. The clock is injected so mint/rotate
// timestamps stay deterministic in tests (same convention as the other adapters).
func NewAccountKeyStore(clock ports.Clock) *AccountKeyStore {
	return &AccountKeyStore{
		byAccount: make(map[string]*accountkey.AccountKey),
		byHash:    make(map[string]string),
		clock:     clock,
	}
}

// Compile-time check that the adapter satisfies the port.
var _ ports.AccountKeyStore = (*AccountKeyStore)(nil)

// PutKey mints a fresh key for accountID and returns the plaintext once. It is
// idempotent in the create==rotate sense: if the account already holds a key, that
// key is superseded (its hash index removed) before the new one is installed, so
// the previous secret is invalidated immediately.
func (s *AccountKeyStore) PutKey(_ context.Context, accountID string) (string, error) {
	if accountID == "" {
		return "", shared.NewValidationError("account_id", "account id is required")
	}
	now := s.clock.Now()
	key, plaintext, err := accountkey.Mint(accountID, now)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.byAccount[accountID]; ok {
		prev.Supersede(now)
		delete(s.byHash, prev.Hash())
	}
	s.byAccount[accountID] = key
	s.byHash[key.Hash()] = accountID
	return plaintext, nil
}

// Rotate is the explicit rotation name; create==rotate, so it delegates to PutKey.
func (s *AccountKeyStore) Rotate(ctx context.Context, accountID string) (string, error) {
	return s.PutKey(ctx, accountID)
}

// AuthenticateAccountKey resolves a presented plaintext secret to its owning account
// id. It hashes the secret and looks the hash up among active keys; a miss (unknown,
// malformed, or superseded secret) returns ("", false) — a single non-oracle failure
// mode. The Verify re-check is belt-and-suspenders: byHash only ever holds active
// hashes, so this cannot resurrect a rotated key.
func (s *AccountKeyStore) AuthenticateAccountKey(_ context.Context, secret string) (string, bool) {
	if secret == "" {
		return "", false
	}
	hash := accountkey.HashSecret(secret)

	s.mu.RLock()
	defer s.mu.RUnlock()
	accountID, ok := s.byHash[hash]
	if !ok {
		return "", false
	}
	key, ok := s.byAccount[accountID]
	if !ok || !key.Verify(secret) {
		return "", false
	}
	return accountID, true
}
