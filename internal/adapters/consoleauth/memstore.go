// Package consoleauth provides the in-memory storage adapter for the console
// login use-cases (SIN-69265): the operator credential, server-side sessions and
// the TOTP replay guard. It satisfies the app-layer ports
// (app.ConsoleCredentialStore, app.SessionStore, app.TOTPReplayStore) with a
// single process-local, concurrency-safe store.
//
// TRADE-OFF (documented, accepted for the first delivery — ADR-0001 Opção B):
// state lives ONLY in process memory. A restart therefore (a) drops every active
// session — operators must log in again, a minor annoyance — and (b) drops the
// provisioned credential, so first-access bootstrap must be re-run with the deploy
// token after each restart. The bootstrap token is delivered out-of-band and the
// route is failure-closed, so this is safe but operationally noisy. A durable,
// encrypted-at-rest sqlite-backed adapter behind these SAME ports is the planned
// follow-up (see the PR / runbook); swapping it in is a wiring change only.
package consoleauth

import (
	"context"
	"sync"
	"time"

	domain "github.com/ia-dev-sindireceita/payment/internal/domain/consoleauth"
)

// MemStore is the in-memory implementation of the console-auth storage ports.
// The zero value is not usable; build it with NewMemStore.
type MemStore struct {
	mu       sync.RWMutex
	cred     domain.Credential
	credSet  bool
	sessions map[string]domain.Session
	lastStep map[string]int64
}

// NewMemStore builds an empty MemStore (no credential provisioned, no sessions).
func NewMemStore() *MemStore {
	return &MemStore{
		sessions: make(map[string]domain.Session),
		lastStep: make(map[string]int64),
	}
}

// --- app.ConsoleCredentialStore ---

// GetCredential returns the provisioned operator credential, or ok=false when none
// has been set yet (pre-bootstrap). It never errors (in-memory).
func (m *MemStore) GetCredential(_ context.Context) (domain.Credential, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cred, m.credSet, nil
}

// SaveCredential stores the operator credential. Bootstrap enforces single-use at
// the use-case layer (it refuses when one is already provisioned); this adapter
// just persists whatever it is handed.
func (m *MemStore) SaveCredential(_ context.Context, c domain.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cred = c
	m.credSet = true
	return nil
}

// --- app.SessionStore ---

// Create stores a new session keyed by its opaque id.
func (m *MemStore) Create(_ context.Context, s domain.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID()] = s
	return nil
}

// Get returns the session for id, or found=false when unknown.
func (m *MemStore) Get(_ context.Context, id string) (domain.Session, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok, nil
}

// Touch advances a session's last-seen instant (idle clock). An unknown id is a
// no-op (the session was already revoked/expired).
func (m *MemStore) Touch(_ context.Context, id string, lastSeen time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[id]; ok {
		m.sessions[id] = s.Touched(lastSeen)
	}
	return nil
}

// Delete revokes a session (logout / expiry cleanup). Idempotent.
func (m *MemStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

// --- app.TOTPReplayStore ---

// LastStep returns the last TOTP step consumed for subject, or 0 when none.
func (m *MemStore) LastStep(_ context.Context, subject string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastStep[subject], nil
}

// SetLastStep records the TOTP step just consumed for subject so it (and any
// earlier step) cannot be replayed.
func (m *MemStore) SetLastStep(_ context.Context, subject string, step int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastStep[subject] = step
	return nil
}
