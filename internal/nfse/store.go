package nfse

import (
	"context"
	"sync"
	"time"
)

// Status is the lifecycle state of an emission.
type Status string

const (
	// StatusPending marks an idempotency reservation: the request claimed its
	// Idempotency-Key and has not finished transmitting yet.
	StatusPending Status = "pending"
	// StatusAuthorized means the ADN accepted and authorised the NFS-e.
	StatusAuthorized Status = "authorized"
	// StatusRejected means the ADN rejected the DPS on a business rule.
	StatusRejected Status = "rejected"
)

// Emission is the persisted record of an NFS-e emission attempt. It is what
// GET /api/v1/nfse/{id} returns and what an idempotent replay reuses. It is
// scoped to TenantID so one tenant can never read another's emission.
type Emission struct {
	// ID is the app-assigned identifier surfaced to the client.
	ID string
	// TenantID owns the record (per-resource authorisation).
	TenantID string
	// IdempotencyKey, when set, dedupes retries of the same logical request.
	IdempotencyKey string
	// EmitterCNPJ is the MEI that emitted (digits only).
	EmitterCNPJ string
	// Competencia is the service month.
	Competencia Competencia
	// ServiceValueCents mirrors the DPS value.
	ServiceValueCents int64
	// Status is pending|authorized|rejected.
	Status Status
	// ChaveAcesso is the ADN access key (50 digits) when authorised.
	ChaveAcesso string
	// NFSeNumber is the ADN-assigned NFS-e number when authorised.
	NFSeNumber string
	// Series / Number identify the DPS (serie / nDPS). When the emitter owns
	// the numbering (WithSequencer) the number is assigned right after the
	// idempotency reservation and saved on the pending record, so a takeover of
	// a stale reservation re-sends the SAME DPS instead of issuing a new one.
	Series string
	Number string
	// TomadorDocument / TomadorName identify the service taker, when informed.
	TomadorDocument string
	TomadorName     string
	// DPSID is the signed DPS element Id, for traceability.
	DPSID string
	// XML is the authorised NFS-e document returned by the ADN (may be empty
	// when the ADN does not echo it).
	XML []byte
	// RejectionCode / RejectionMessage carry the first ADN business error when
	// Status is rejected.
	RejectionCode    string
	RejectionMessage string
	// CreatedAt is when the record was stored (UTC).
	CreatedAt time.Time
}

// Store persists emissions for status lookup and idempotent replay. The MVP
// ships MemoryStore (documented in-memory adapter, quality rule 5); a Postgres
// adapter lives in internal/nfse/pgstore.
type Store interface {
	// Reserve atomically claims p.IdempotencyKey for p.TenantID before the
	// DPS is transmitted, storing p (Status pending) under p.ID. It closes the
	// window where two concurrent requests with the same key both miss the
	// replay check and both transmit — i.e. issue two real NFS-e.
	//
	//   - key free: stores p and returns reserved=true;
	//   - key held by a finished emission: returns it, reserved=false (replay);
	//   - key held by a pending reservation created at or after staleBefore:
	//     returns ErrEmissionInFlight;
	//   - key held by a pending reservation older than staleBefore (its holder
	//     crashed mid-flight): takes it over, reserved=true, and returns the
	//     stale record as prior so the caller can reuse its DPS number.
	//
	// p.IdempotencyKey must not be empty.
	Reserve(ctx context.Context, p Emission, staleBefore time.Time) (prior Emission, reserved bool, err error)
	// Release drops the pending reservation id for (tenantID, key), freeing
	// the key for a retry. A finished emission, or a reservation already taken
	// over by another id, is left untouched.
	Release(ctx context.Context, tenantID, key, id string) error
	// Save stores (or overwrites on the same ID) an emission. An emission that
	// carries an IdempotencyKey must be saved under the ID that Reserve claimed.
	Save(ctx context.Context, e Emission) error
	// GetByID returns the emission with id owned by tenantID, or ErrNotFound.
	// A record owned by a different tenantID is reported as ErrNotFound (no
	// existence leak across tenants).
	GetByID(ctx context.Context, tenantID, id string) (Emission, error)
	// GetByIdempotencyKey returns a prior emission for (tenantID, key), or
	// ErrNotFound. An empty key never matches.
	GetByIdempotencyKey(ctx context.Context, tenantID, key string) (Emission, error)
}

// MemoryStore is a tenant-scoped, in-memory Store. It mirrors the observable
// semantics a Postgres adapter must provide: per-tenantID isolation on read,
// idempotency-key dedup, and ErrNotFound (never a cross-tenant leak). It is
// safe for concurrent use.
type MemoryStore struct {
	mu   sync.RWMutex
	byID map[string]Emission // id -> emission
	idem map[string]string   // tenantID\x00key -> id
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID: make(map[string]Emission),
		idem: make(map[string]string),
	}
}

func idemKey(tenantID, key string) string { return tenantID + "\x00" + key }

// Save stores e under its ID and, when it carries an idempotency key, indexes
// it for replay.
func (m *MemoryStore) Save(_ context.Context, e Emission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[e.ID] = e
	if e.IdempotencyKey != "" {
		m.idem[idemKey(e.TenantID, e.IdempotencyKey)] = e.ID
	}
	return nil
}

// GetByID returns the emission only when tenantID owns it.
func (m *MemoryStore) GetByID(_ context.Context, tenantID, id string) (Emission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.byID[id]
	if !ok || e.TenantID != tenantID {
		return Emission{}, ErrNotFound
	}
	return e, nil
}

// Reserve claims (p.TenantID, p.IdempotencyKey) for p.ID; see Store.Reserve.
func (m *MemoryStore) Reserve(_ context.Context, p Emission, staleBefore time.Time) (Emission, bool, error) {
	if p.IdempotencyKey == "" {
		return Emission{}, false, ErrEmptyIdempotencyKey
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := idemKey(p.TenantID, p.IdempotencyKey)
	if id, ok := m.idem[k]; ok {
		if prior, ok := m.byID[id]; ok {
			if prior.Status != StatusPending {
				return prior, false, nil
			}
			if !prior.CreatedAt.Before(staleBefore) {
				return Emission{}, false, ErrEmissionInFlight
			}
			delete(m.byID, id) // stale reservation: take it over
			m.byID[p.ID] = p
			m.idem[k] = p.ID
			return prior, true, nil
		}
	}
	m.byID[p.ID] = p
	m.idem[k] = p.ID
	return Emission{}, true, nil
}

// Release drops the pending reservation id; see Store.Release.
func (m *MemoryStore) Release(_ context.Context, tenantID, key, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := idemKey(tenantID, key)
	if m.idem[k] != id {
		return nil
	}
	if e, ok := m.byID[id]; ok && e.Status != StatusPending {
		return nil
	}
	delete(m.byID, id)
	delete(m.idem, k)
	return nil
}

// GetByIdempotencyKey returns a prior emission for (tenantID, key).
func (m *MemoryStore) GetByIdempotencyKey(_ context.Context, tenantID, key string) (Emission, error) {
	if key == "" {
		return Emission{}, ErrNotFound
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.idem[idemKey(tenantID, key)]
	if !ok {
		return Emission{}, ErrNotFound
	}
	e, ok := m.byID[id]
	if !ok {
		return Emission{}, ErrNotFound
	}
	return e, nil
}
