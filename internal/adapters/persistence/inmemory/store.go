// Package inmemory is an in-memory implementation of the repository ports. It
// exists to (a) demonstrate adapter plugability — swapping it for the SQLite
// adapter is pure wiring in cmd, with no change to the domain or use-cases — and
// (b) provide a fast, production-faithful store for tests (it enforces the same
// tenant scoping, idempotency-key uniqueness and transactional unit-of-work
// invariants as the SQLite adapter).
package inmemory

import (
	"context"
	"sort"
	"sync"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Store is a concurrency-safe in-memory repository.
type Store struct {
	mu        sync.RWMutex
	tenants   map[string]*tenant.Tenant
	payments  map[string]*payment.Payment        // keyed by tenantID+"\x00"+id
	pricing   map[string]billing.EndpointPricing // keyed by tenantID+"\x00"+endpoint
	ledger    []billing.LedgerEntry
	processed map[string]struct{} // keyed by tenantID+"\x00"+eventKey
}

// NewStore returns an empty in-memory store.
func NewStore() *Store {
	return &Store{
		tenants:   make(map[string]*tenant.Tenant),
		payments:  make(map[string]*payment.Payment),
		pricing:   make(map[string]billing.EndpointPricing),
		processed: make(map[string]struct{}),
	}
}

var (
	_ ports.PaymentRepository   = (*Store)(nil)
	_ ports.TenantRepository    = (*Store)(nil)
	_ ports.PricingRepository   = (*Store)(nil)
	_ ports.LedgerRepository    = (*Store)(nil)
	_ ports.ProcessedEventStore = (*Store)(nil)
	_ ports.Repository          = (*Store)(nil)
	_ ports.UnitOfWork          = (*Store)(nil)
)

func key(a, b string) string { return a + "\x00" + b }

// clonePayment returns a defensive copy. Payment fields are all value types
// (string, Money, Status, time.Time), so a struct copy is a deep copy. Storing
// and returning clones keeps callers from mutating persisted state in place,
// which is what makes the snapshot-based rollback in WithinTx correct.
func clonePayment(p *payment.Payment) *payment.Payment {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

// --- Public (locking) repository methods ---

// SaveTenant stores a tenant.
func (s *Store) SaveTenant(ctx context.Context, t *tenant.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveTenant(t)
}

// FindTenantByID returns a tenant or ErrNotFound.
func (s *Store) FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findTenantByID(id)
}

// ListTenants returns every tenant, newest-first (createdAt desc, id desc as a
// deterministic tie-break). Mirrors the SQLite adapter's ordering.
func (s *Store) ListTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*tenant.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := out[i].CreatedAt(), out[j].CreatedAt()
		if ci.Equal(cj) {
			return out[i].ID() > out[j].ID()
		}
		return ci.After(cj)
	})
	return out, nil
}

// SavePayment stores a payment scoped by tenant, enforcing per-tenant
// idempotency-key uniqueness (returns shared.ErrConflict on violation).
func (s *Store) SavePayment(ctx context.Context, p *payment.Payment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.savePayment(p)
}

// FindPaymentByID returns a tenant-scoped payment or ErrNotFound.
func (s *Store) FindPaymentByID(ctx context.Context, tenantID, id string) (*payment.Payment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findPaymentByID(tenantID, id)
}

// FindPaymentByIdempotencyKey scans the tenant's payments for the key.
func (s *Store) FindPaymentByIdempotencyKey(ctx context.Context, tenantID, idemKey string) (*payment.Payment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findPaymentByIdempotencyKey(tenantID, idemKey)
}

// FindPaymentByTxID scans the tenant's payments for the tx id.
func (s *Store) FindPaymentByTxID(ctx context.Context, tenantID, txID string) (*payment.Payment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findPaymentByTxID(tenantID, txID)
}

// GetEndpointPrice returns the price for a tenant × endpoint or ErrNotFound.
func (s *Store) GetEndpointPrice(ctx context.Context, tenantID, endpoint string) (billing.EndpointPricing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getEndpointPrice(tenantID, endpoint)
}

// UpsertEndpointPrice stores a pricing rule.
func (s *Store) UpsertEndpointPrice(ctx context.Context, p billing.EndpointPricing) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upsertEndpointPrice(p)
}

// ListEndpointPrices returns a tenant's pricing rules ordered by endpoint.
func (s *Store) ListEndpointPrices(ctx context.Context, tenantID string) ([]billing.EndpointPricing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]billing.EndpointPricing, 0)
	for _, p := range s.pricing {
		if p.TenantID() == tenantID {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Endpoint() < out[j].Endpoint() })
	return out, nil
}

// AppendLedgerEntry appends a billable event.
func (s *Store) AppendLedgerEntry(ctx context.Context, e billing.LedgerEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appendLedgerEntry(e)
}

// MarkProcessed records an event key, returning false on duplicate.
func (s *Store) MarkProcessed(ctx context.Context, tenantID, eventKey string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.markProcessed(tenantID, eventKey)
}

// ListLedgerEntries returns a tenant's ledger entries, newest-first.
func (s *Store) ListLedgerEntries(ctx context.Context, tenantID string) ([]billing.LedgerEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]billing.LedgerEntry, 0)
	for _, e := range s.ledger {
		if e.TenantID() == tenantID {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].At(), out[j].At()
		if ai.Equal(aj) {
			return out[i].ID() > out[j].ID()
		}
		return ai.After(aj)
	})
	return out, nil
}

// LedgerLen returns the number of ledger entries (test/inspection helper).
func (s *Store) LedgerLen() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ledger)
}

// --- Unit of work ---

// WithinTx runs fn inside a single atomic transaction. The whole store is locked
// for the duration (serializing writers, which is what lets the idempotency-key
// uniqueness check stand in for the SQLite unique index). On a nil return the
// staged changes stand; on an error the store is rolled back to the snapshot
// taken before fn ran. fn receives a tenant-scoped ports.Repository that operates
// without re-locking (the lock is already held).
func (s *Store) WithinTx(ctx context.Context, fn func(ports.Repository) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.snapshot()
	if err := fn(txView{s}); err != nil {
		s.restore(snap)
		return err
	}
	return nil
}

// snapshot captures shallow copies of the maps and the ledger slice. Because the
// lock-free mutators never mutate stored aggregates in place (they replace map
// entries with fresh clones), copying the containers is sufficient for rollback.
type snapshot struct {
	tenants   map[string]*tenant.Tenant
	payments  map[string]*payment.Payment
	pricing   map[string]billing.EndpointPricing
	ledger    []billing.LedgerEntry
	processed map[string]struct{}
}

func (s *Store) snapshot() snapshot {
	tenants := make(map[string]*tenant.Tenant, len(s.tenants))
	for k, v := range s.tenants {
		tenants[k] = v
	}
	payments := make(map[string]*payment.Payment, len(s.payments))
	for k, v := range s.payments {
		payments[k] = v
	}
	pricing := make(map[string]billing.EndpointPricing, len(s.pricing))
	for k, v := range s.pricing {
		pricing[k] = v
	}
	processed := make(map[string]struct{}, len(s.processed))
	for k, v := range s.processed {
		processed[k] = v
	}
	ledger := make([]billing.LedgerEntry, len(s.ledger))
	copy(ledger, s.ledger)
	return snapshot{tenants: tenants, payments: payments, pricing: pricing, ledger: ledger, processed: processed}
}

func (s *Store) restore(snap snapshot) {
	s.tenants = snap.tenants
	s.payments = snap.payments
	s.pricing = snap.pricing
	s.ledger = snap.ledger
	s.processed = snap.processed
}

// --- Lock-free core (callers must hold s.mu) ---

func (s *Store) saveTenant(t *tenant.Tenant) error {
	s.tenants[t.ID()] = t
	return nil
}

func (s *Store) findTenantByID(id string) (*tenant.Tenant, error) {
	t, ok := s.tenants[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (s *Store) savePayment(p *payment.Payment) error {
	// Per-tenant idempotency-key uniqueness: a different payment id may not reuse
	// a key already taken in the same tenant (mirrors ux_payments_tenant_idempotency).
	for _, ex := range s.payments {
		if ex.TenantID() == p.TenantID() && ex.IdempotencyKey() == p.IdempotencyKey() && ex.ID() != p.ID() {
			return shared.ErrConflict
		}
	}
	s.payments[key(p.TenantID(), p.ID())] = clonePayment(p)
	return nil
}

func (s *Store) findPaymentByID(tenantID, id string) (*payment.Payment, error) {
	p, ok := s.payments[key(tenantID, id)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return clonePayment(p), nil
}

func (s *Store) findPaymentByIdempotencyKey(tenantID, idemKey string) (*payment.Payment, error) {
	for _, p := range s.payments {
		if p.TenantID() == tenantID && p.IdempotencyKey() == idemKey {
			return clonePayment(p), nil
		}
	}
	return nil, shared.ErrNotFound
}

func (s *Store) findPaymentByTxID(tenantID, txID string) (*payment.Payment, error) {
	for _, p := range s.payments {
		if p.TenantID() == tenantID && p.TxID() == txID {
			return clonePayment(p), nil
		}
	}
	return nil, shared.ErrNotFound
}

func (s *Store) getEndpointPrice(tenantID, endpoint string) (billing.EndpointPricing, error) {
	p, ok := s.pricing[key(tenantID, endpoint)]
	if !ok {
		return billing.EndpointPricing{}, shared.ErrNotFound
	}
	return p, nil
}

func (s *Store) upsertEndpointPrice(p billing.EndpointPricing) error {
	s.pricing[key(p.TenantID(), p.Endpoint())] = p
	return nil
}

func (s *Store) appendLedgerEntry(e billing.LedgerEntry) error {
	s.ledger = append(s.ledger, e)
	return nil
}

func (s *Store) markProcessed(tenantID, eventKey string) (bool, error) {
	k := key(tenantID, eventKey)
	if _, ok := s.processed[k]; ok {
		return false, nil
	}
	s.processed[k] = struct{}{}
	return true, nil
}

// txView is the tenant-scoped ports.Repository handed to a WithinTx callback. It
// delegates to the lock-free core; the surrounding WithinTx holds s.mu.
type txView struct{ s *Store }

var _ ports.Repository = txView{}

func (v txView) SaveTenant(ctx context.Context, t *tenant.Tenant) error {
	return v.s.saveTenant(t)
}

func (v txView) FindTenantByID(ctx context.Context, id string) (*tenant.Tenant, error) {
	return v.s.findTenantByID(id)
}

func (v txView) SavePayment(ctx context.Context, p *payment.Payment) error {
	return v.s.savePayment(p)
}

func (v txView) FindPaymentByID(ctx context.Context, tenantID, id string) (*payment.Payment, error) {
	return v.s.findPaymentByID(tenantID, id)
}

func (v txView) FindPaymentByIdempotencyKey(ctx context.Context, tenantID, idemKey string) (*payment.Payment, error) {
	return v.s.findPaymentByIdempotencyKey(tenantID, idemKey)
}

func (v txView) FindPaymentByTxID(ctx context.Context, tenantID, txID string) (*payment.Payment, error) {
	return v.s.findPaymentByTxID(tenantID, txID)
}

func (v txView) GetEndpointPrice(ctx context.Context, tenantID, endpoint string) (billing.EndpointPricing, error) {
	return v.s.getEndpointPrice(tenantID, endpoint)
}

func (v txView) UpsertEndpointPrice(ctx context.Context, p billing.EndpointPricing) error {
	return v.s.upsertEndpointPrice(p)
}

func (v txView) AppendLedgerEntry(ctx context.Context, e billing.LedgerEntry) error {
	return v.s.appendLedgerEntry(e)
}

func (v txView) MarkProcessed(ctx context.Context, tenantID, eventKey string) (bool, error) {
	return v.s.markProcessed(tenantID, eventKey)
}
