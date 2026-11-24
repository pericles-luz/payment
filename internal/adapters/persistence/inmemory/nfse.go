package inmemory

import (
	"context"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/nfse"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// NFS-e emitter state (mirrors migration 0020). Emission records take part in
// the unit of work (snapshot/restore); the reservation, numbering and DANFSe
// cache are plain locked operations, like their SQL counterparts.

var (
	_ ports.NFSeEmissionRepository = txView{}
	_ ports.NFSeStore              = (*Store)(nil)
)

// NFSeCerts returns the in-memory certificate store.
func (s *Store) NFSeCerts() *custody.MemoryCertStore { return s.nfseCerts }

func (s *Store) saveNFSeEmission(e nfse.Emission) error {
	if e.IdempotencyKey != "" {
		for _, ex := range s.nfseEmissions {
			if ex.TenantID == e.TenantID && ex.IdempotencyKey == e.IdempotencyKey && ex.ID != e.ID {
				return shared.ErrConflict
			}
		}
	}
	e.XML = append([]byte(nil), e.XML...)
	if prev, ok := s.nfseEmissions[key(e.TenantID, e.ID)]; ok {
		e.CreatedAt = prev.CreatedAt // like the SQL upsert: creation time is immutable
	}
	s.nfseEmissions[key(e.TenantID, e.ID)] = e
	return nil
}

func (s *Store) findNFSeEmission(tenantID, id string) (nfse.Emission, error) {
	e, ok := s.nfseEmissions[key(tenantID, id)]
	if !ok {
		return nfse.Emission{}, shared.ErrNotFound
	}
	return e, nil
}

func (s *Store) findNFSeByIdem(tenantID, idemKey string) (nfse.Emission, bool) {
	if idemKey == "" {
		return nfse.Emission{}, false
	}
	for _, e := range s.nfseEmissions {
		if e.TenantID == tenantID && e.IdempotencyKey == idemKey {
			return e, true
		}
	}
	return nfse.Emission{}, false
}

func (v txView) SaveNFSeEmission(_ context.Context, e nfse.Emission) error {
	return v.s.saveNFSeEmission(e)
}

func (v txView) FindNFSeEmission(_ context.Context, tenantID, id string) (nfse.Emission, error) {
	return v.s.findNFSeEmission(tenantID, id)
}

// SaveNFSeEmission stores (or overwrites) an emission.
func (s *Store) SaveNFSeEmission(_ context.Context, e nfse.Emission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveNFSeEmission(e)
}

// FindNFSeEmission returns a tenant-scoped emission.
func (s *Store) FindNFSeEmission(_ context.Context, tenantID, id string) (nfse.Emission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findNFSeEmission(tenantID, id)
}

// FindNFSeEmissionByIdempotencyKey returns the emission holding (tenant, key).
func (s *Store) FindNFSeEmissionByIdempotencyKey(_ context.Context, tenantID, idemKey string) (nfse.Emission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.findNFSeByIdem(tenantID, idemKey)
	if !ok {
		return nfse.Emission{}, shared.ErrNotFound
	}
	return e, nil
}

// ReserveNFSeEmission claims (tenant, key) for p; see ports.NFSeStore.
func (s *Store) ReserveNFSeEmission(_ context.Context, p nfse.Emission, staleBefore time.Time) (nfse.Emission, bool, error) {
	if p.IdempotencyKey == "" {
		return nfse.Emission{}, false, nfse.ErrEmptyIdempotencyKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, ok := s.findNFSeByIdem(p.TenantID, p.IdempotencyKey)
	if ok {
		if prior.Status != nfse.StatusPending {
			return prior, false, nil
		}
		if !prior.CreatedAt.Before(staleBefore) {
			return nfse.Emission{}, false, nfse.ErrEmissionInFlight
		}
		delete(s.nfseEmissions, key(prior.TenantID, prior.ID))
	}
	s.nfseEmissions[key(p.TenantID, p.ID)] = p
	if ok {
		return prior, true, nil
	}
	return nfse.Emission{}, true, nil
}

// ReleaseNFSeEmission drops a pending reservation.
func (s *Store) ReleaseNFSeEmission(_ context.Context, tenantID, idemKey, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, id)
	if e, ok := s.nfseEmissions[k]; ok && e.IdempotencyKey == idemKey && e.Status == nfse.StatusPending {
		delete(s.nfseEmissions, k)
		delete(s.nfseDANFSe, k)
	}
	return nil
}

// NextDPSNumber increments the (CNPJ, série) sequence.
func (s *Store) NextDPSNumber(_ context.Context, emitterCNPJ, series string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(emitterCNPJ, series)
	s.nfseSeq[k]++
	return s.nfseSeq[k], nil
}

// SaveNFSeDANFSe caches the PDF of a tenant-owned emission.
func (s *Store) SaveNFSeDANFSe(_ context.Context, tenantID, id string, pdf []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, id)
	if _, ok := s.nfseEmissions[k]; !ok {
		return shared.ErrNotFound
	}
	s.nfseDANFSe[k] = append([]byte(nil), pdf...)
	return nil
}

// FindNFSeDANFSe returns the cached PDF or shared.ErrNotFound.
func (s *Store) FindNFSeDANFSe(_ context.Context, tenantID, id string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pdf, ok := s.nfseDANFSe[key(tenantID, id)]
	if !ok || len(pdf) == 0 {
		return nil, shared.ErrNotFound
	}
	return pdf, nil
}
