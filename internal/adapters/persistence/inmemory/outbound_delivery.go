package inmemory

import (
	"context"
	"sync"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
)

// OutboundDeliveryStore is the in-process implementation of the F1 inbound→Conta
// attribution outbox (app.OutboundDeliveryQueue + app.DeadLetterSink, SIN-69491), used
// in stub/dev wiring and tests exactly like the durable sqlite OutboundDeliveryStore.
// It mirrors that adapter's behaviour: idempotent enqueue/park keyed by (accountID,
// eventKey) / (tenantID, eventKey) so a redelivered inbound event never materialises a
// duplicate, and account-scoped pending reads.
//
// It snapshots each aggregate's fields into a flat record (no shared pointer into the
// store) and rehydrates a fresh aggregate on read, matching the sqlite round-trip.
type OutboundDeliveryStore struct {
	mu sync.RWMutex
	// deliveries preserves insertion order; seenDelivery dedups (accountID|eventKey).
	deliveries  []storedDelivery
	seenDeliver map[string]struct{}
	// deadLetters preserves insertion order; seenDead dedups (tenantID|eventKey).
	deadLetters []storedDeadLetter
	seenDead    map[string]struct{}
}

type storedDelivery struct {
	id        string
	accountID string
	tenantID  string
	eventKey  string
	txID      string
	eventType string
	status    outboundqueue.DeliveryStatus
	createdAt time.Time
}

type storedDeadLetter struct {
	id        string
	tenantID  string
	eventKey  string
	txID      string
	eventType string
	reason    outboundqueue.Reason
	createdAt time.Time
}

// NewOutboundDeliveryStore builds an empty store.
func NewOutboundDeliveryStore() *OutboundDeliveryStore {
	return &OutboundDeliveryStore{
		seenDeliver: make(map[string]struct{}),
		seenDead:    make(map[string]struct{}),
	}
}

// EnqueueDelivery appends an attributed Delivery, idempotent on (accountID, eventKey):
// a duplicate inbound event is a silent no-op (matching the sqlite ON CONFLICT).
func (s *OutboundDeliveryStore) EnqueueDelivery(_ context.Context, d *outboundqueue.Delivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := d.AccountID() + "|" + d.EventKey()
	if _, ok := s.seenDeliver[key]; ok {
		return nil
	}
	s.seenDeliver[key] = struct{}{}
	s.deliveries = append(s.deliveries, storedDelivery{
		id:        d.ID(),
		accountID: d.AccountID(),
		tenantID:  d.TenantID(),
		eventKey:  d.EventKey(),
		txID:      d.TxID(),
		eventType: d.EventType(),
		status:    d.Status(),
		createdAt: d.CreatedAt(),
	})
	return nil
}

// DeadLetter appends a parked event, idempotent on (tenantID, eventKey).
func (s *OutboundDeliveryStore) DeadLetter(_ context.Context, dl *outboundqueue.DeadLetter) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := dl.TenantID() + "|" + dl.EventKey()
	if _, ok := s.seenDead[key]; ok {
		return nil
	}
	s.seenDead[key] = struct{}{}
	s.deadLetters = append(s.deadLetters, storedDeadLetter{
		id:        dl.ID(),
		tenantID:  dl.TenantID(),
		eventKey:  dl.EventKey(),
		txID:      dl.TxID(),
		eventType: dl.EventType(),
		reason:    dl.Reason(),
		createdAt: dl.CreatedAt(),
	})
	return nil
}

// PendingDeliveries returns a Conta's pending outbox deliveries in insertion order. It
// is account-scoped (A01): only the given Conta's rows are returned.
func (s *OutboundDeliveryStore) PendingDeliveries(_ context.Context, accountID string) ([]*outboundqueue.Delivery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*outboundqueue.Delivery
	for _, r := range s.deliveries {
		if r.accountID != accountID || r.status != outboundqueue.StatusPending {
			continue
		}
		out = append(out, outboundqueue.RehydrateDelivery(
			r.id, r.accountID, r.tenantID, r.eventKey, r.txID, r.eventType, r.status, r.createdAt))
	}
	return out, nil
}

// DeadLetters returns all parked dead-letters in insertion order.
func (s *OutboundDeliveryStore) DeadLetters(_ context.Context) ([]*outboundqueue.DeadLetter, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*outboundqueue.DeadLetter
	for _, r := range s.deadLetters {
		out = append(out, outboundqueue.RehydrateDeadLetter(
			r.id, r.tenantID, r.eventKey, r.txID, r.eventType, r.reason, r.createdAt))
	}
	return out, nil
}
