package inmemory

import (
	"context"
	"sort"

	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// This file implements the PIX Automático recurrence ports (SIN-66037) on the
// in-memory store, mirroring the SQLite adapter's behaviour: tenant-scoped reads,
// upsert-on-save keyed by idRec / txid, and clone-in/clone-out so stored
// aggregates are never mutated in place (which is what keeps the WithinTx
// snapshot rollback correct, exactly like payments).

// cloneRec returns a defensive copy. recurrence.Rec's fields are all value types
// (strings, int64, time.Time, the Devedor value struct), so a struct copy is a
// deep copy.
func cloneRec(r *recurrence.Rec) *recurrence.Rec {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// cloneCobR returns a defensive copy (all CobR fields are value types).
func cloneCobR(c *recurrence.CobR) *recurrence.CobR {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// --- Public (locking) methods ---

// SaveRec upserts a mandate scoped by tenant.
func (s *Store) SaveRec(ctx context.Context, r *recurrence.Rec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveRec(r)
}

// FindRecByID returns a tenant-scoped mandate or shared.ErrNotFound.
func (s *Store) FindRecByID(ctx context.Context, tenantID, idRec string) (*recurrence.Rec, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findRecByID(tenantID, idRec)
}

// SaveCobR upserts a charge instance scoped by tenant.
func (s *Store) SaveCobR(ctx context.Context, c *recurrence.CobR) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveCobR(c)
}

// FindCobRByTxID returns a tenant-scoped charge instance or shared.ErrNotFound.
func (s *Store) FindCobRByTxID(ctx context.Context, tenantID, txID string) (*recurrence.CobR, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findCobRByTxID(tenantID, txID)
}

// ListCobRByRec returns a mandate's charge instances, due-date ascending (txid as
// a deterministic tie-break). Mirrors the SQLite adapter's ordering. Tenant-scoped.
func (s *Store) ListCobRByRec(ctx context.Context, tenantID, idRec string) ([]*recurrence.CobR, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*recurrence.CobR, 0)
	for _, c := range s.cobrs {
		if c.TenantID() == tenantID && c.IDRec() == idRec {
			out = append(out, cloneCobR(c))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Vencimento() == out[j].Vencimento() {
			return out[i].TxID() < out[j].TxID()
		}
		return out[i].Vencimento() < out[j].Vencimento()
	})
	return out, nil
}

// --- Lock-free core (callers must hold s.mu) ---

func (s *Store) saveRec(r *recurrence.Rec) error {
	s.recs[key(r.TenantID(), r.IDRec())] = cloneRec(r)
	return nil
}

func (s *Store) findRecByID(tenantID, idRec string) (*recurrence.Rec, error) {
	r, ok := s.recs[key(tenantID, idRec)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return cloneRec(r), nil
}

func (s *Store) saveCobR(c *recurrence.CobR) error {
	s.cobrs[key(c.TenantID(), c.TxID())] = cloneCobR(c)
	return nil
}

func (s *Store) findCobRByTxID(tenantID, txID string) (*recurrence.CobR, error) {
	c, ok := s.cobrs[key(tenantID, txID)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return cloneCobR(c), nil
}

// --- txView (unit-of-work) delegations ---

func (v txView) SaveRec(ctx context.Context, r *recurrence.Rec) error {
	return v.s.saveRec(r)
}

func (v txView) FindRecByID(ctx context.Context, tenantID, idRec string) (*recurrence.Rec, error) {
	return v.s.findRecByID(tenantID, idRec)
}

func (v txView) SaveCobR(ctx context.Context, c *recurrence.CobR) error {
	return v.s.saveCobR(c)
}

func (v txView) FindCobRByTxID(ctx context.Context, tenantID, txID string) (*recurrence.CobR, error) {
	return v.s.findCobRByTxID(tenantID, txID)
}
