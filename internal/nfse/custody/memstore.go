package custody

import (
	"context"
	"crypto/x509"
	"sync"
)

// MemoryCertStore is an in-process, tenant-scoped CertStore. It is the
// documented in-memory adapter (quality rule 5) that mirrors the production
// Postgres adapter's observable semantics exactly: strict per-tenant isolation
// (a companyID can only ever read/write its own row), public material only, and
// crypto-shred on Delete. It backs the homologation POC and the isolation /
// no-leak regression tests.
//
// It is safe for concurrent use.
type MemoryCertStore struct {
	mu   sync.RWMutex
	rows map[string]memRow

	// onStaleSerial, when set, is invoked with (companyID, oldSerial) when PutA1
	// replaces an on-file certificate with a DIFFERENT serial (re-import /
	// rotation). It backs the a1_cert_expiry_days stale-series cleanup so the old
	// serial's gauge child is dropped and stops firing NFSeA1CertExpired forever
	// (SIN-67763). Set once at construction; it is read under no lock so it must
	// not be mutated after the store is shared.
	onStaleSerial func(companyID, oldSerial string)
}

type memRow struct {
	chain []*x509.Certificate
	meta  A1Meta
}

// MemoryCertStoreOption configures a MemoryCertStore at construction.
type MemoryCertStoreOption func(*MemoryCertStore)

// WithStaleSeriesObserver registers a hook invoked with (companyID, oldSerial)
// whenever PutA1 replaces an on-file certificate with a DIFFERENT serial — a
// re-import / rotation. It exists so the caller can drop the previous serial's
// a1_cert_expiry_days child from the scrape (SIN-67763): without it the old
// serial keeps exposing its last (often negative) value forever, firing
// NFSeA1CertExpired for a serial that has already been rotated away and possibly
// masking a real expiry on the new serial. Pass metrics.CertExpiryMetrics.Delete.
func WithStaleSeriesObserver(fn func(companyID, oldSerial string)) MemoryCertStoreOption {
	return func(s *MemoryCertStore) { s.onStaleSerial = fn }
}

// compile-time assertion that MemoryCertStore also satisfies the optional
// CertLister capability the proactive expiry sweep type-asserts (SIN-67762).
var _ CertLister = (*MemoryCertStore)(nil)

// NewMemoryCertStore returns an empty in-memory CertStore.
func NewMemoryCertStore(opts ...MemoryCertStoreOption) *MemoryCertStore {
	s := &MemoryCertStore{rows: make(map[string]memRow)}
	for _, o := range opts {
		o(s)
	}
	return s
}

// ListMeta returns the non-secret metadata for every custodied tenant, powering
// the proactive a1_cert_expiry_days sweep (SIN-67762). It copies out only the
// company_id + A1Meta under the read lock — never the chain — so a sweep never
// forces the store to materialise N certificate chains it does not need.
func (s *MemoryCertStore) ListMeta(_ context.Context) ([]CertMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CertMeta, 0, len(s.rows))
	for id, row := range s.rows {
		out = append(out, CertMeta{CompanyID: id, Meta: row.meta})
	}
	return out, nil
}

// PutA1 stores or replaces the public chain + metadata for companyID. The chain
// is defensively copied so a later mutation by the caller cannot alter stored
// state. Returns ErrEmptyCompanyID / ErrEmptyChain on invalid input.
func (s *MemoryCertStore) PutA1(_ context.Context, companyID string, chain []*x509.Certificate, meta A1Meta) error {
	if companyID == "" {
		return ErrEmptyCompanyID
	}
	if len(chain) == 0 {
		return ErrEmptyChain
	}
	cp := make([]*x509.Certificate, len(chain))
	for i, c := range chain {
		if c == nil {
			return ErrEmptyChain
		}
		cp[i] = c
	}
	s.mu.Lock()
	old, existed := s.rows[companyID]
	s.rows[companyID] = memRow{chain: cp, meta: meta}
	s.mu.Unlock()
	// Re-import onto a new serial: drop the previous serial's stale gauge child.
	// The hook runs OUTSIDE the lock (it may touch a Prometheus collector) and
	// only when the serial actually changed — a same-serial re-Put (metadata
	// refresh) leaves the live series alone (SIN-67763).
	if existed && s.onStaleSerial != nil && old.meta.Serial != "" && old.meta.Serial != meta.Serial {
		s.onStaleSerial(companyID, old.meta.Serial)
	}
	return nil
}

// Get returns companyID's public chain + metadata, or ErrCertNotFound. The
// lookup is keyed strictly by companyID, so tenant A can never read tenant B.
func (s *MemoryCertStore) Get(_ context.Context, companyID string) ([]*x509.Certificate, A1Meta, error) {
	if companyID == "" {
		return nil, A1Meta{}, ErrEmptyCompanyID
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	row, ok := s.rows[companyID]
	if !ok {
		return nil, A1Meta{}, ErrCertNotFound
	}
	cp := make([]*x509.Certificate, len(row.chain))
	copy(cp, row.chain)
	return cp, row.meta, nil
}

// Delete removes companyID's stored chain + metadata (crypto-shred trigger).
// Deleting a tenant with nothing on file is a no-op.
func (s *MemoryCertStore) Delete(_ context.Context, companyID string) error {
	if companyID == "" {
		return ErrEmptyCompanyID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, companyID)
	return nil
}
