// Package outboundqueue holds the two aggregates of the inbound→Conta attribution
// step of "webhook de saída por Conta" (SIN-69491, F1 of SIN-69486, model (b)
// ADR-0011): the Delivery (an inbound event durably ATTRIBUTED to its owning Conta
// and materialised on a per-Conta outbox for F2 to forward) and the DeadLetter (an
// inbound event that could NOT be attributed to a Conta, parked for inspection/replay
// instead of being dropped or — critically — mis-delivered to another Conta).
//
// This phase ships ONLY the attribution + durable materialisation; there is NO network
// forward yet (that is F2, gated by the SSRF/HMAC threat model SIN-69489) and the whole
// surface is DARK behind the same PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK flag as F0. Nothing
// here originates outbound I/O.
//
// Security posture (derives the shape):
//   - A01 / isolation: a Delivery is ALWAYS keyed by the accountID resolved
//     SERVER-SIDE from the authenticated inbound event (never from the payload). An
//     event whose owner cannot be determined becomes a DeadLetter — never a Delivery
//     under a "best-guess" Conta, never a fallback to some other endpoint.
//   - Fail-closed: unattributable ⇒ DeadLetter (persisted), never silently dropped.
//   - No secret, no PII at rest: neither aggregate carries the signing secret or the
//     raw event body. They hold only internal opaque identifiers (accountID, tenantID,
//     txID) and the dedup event_key — enough for F2 to reconcile the authoritative
//     state and build/sign the delivery itself, and enough for an operator to inspect
//     or replay. The devedor PII that a Pix payload can carry (see sin-68744) is
//     deliberately NOT copied here, so this outbox is not a new PII-at-rest surface and
//     needs no envelope encryption (contrast the F0 config store, which holds the HMAC
//     secret and IS sealed).
//
// Pure domain: standard library plus the shared errors only — no database/sql, no
// net/http, no vendor SDK.
package outboundqueue

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// DeliveryStatus is the lifecycle state of an outbox Delivery. F1 only ever writes
// StatusPending (materialise-and-park); F2 owns the delivered/failed transitions when
// it consumes the outbox, so the type is defined here but the transition surface is
// intentionally left for F2.
type DeliveryStatus string

const (
	// StatusPending is the initial state of a freshly attributed Delivery: attributed
	// to its Conta and waiting on the outbox for F2 to forward. It is the ONLY status
	// F1 writes.
	StatusPending DeliveryStatus = "pending"

	// StatusDelivered is the terminal success state F2 reaches when the Conta's endpoint
	// accepts a forward (2xx). F2 consumes the outbox as a work queue — a delivered row
	// leaves the queue — so this value is used to describe/audit the transition rather
	// than persisted long-term; it is defined here so the lifecycle vocabulary lives with
	// the aggregate.
	StatusDelivered DeliveryStatus = "delivered"
)

// Reason is the closed set of causes for parking an inbound event as a DeadLetter.
// F1 only produces ReasonUnresolvable (the owning Conta could not be determined);
// F2 will extend the set with delivery-time causes (exhausted retries, inactive
// endpoint) when it owns the forward.
type Reason string

const (
	// ReasonUnresolvable marks an inbound event whose owning Conta could not be
	// determined at attribution time (the tenant→account resolution failed). It is a
	// fail-closed outcome: the event is parked for inspection/replay rather than
	// forwarded to a guessed Conta. F1 produces this one.
	ReasonUnresolvable Reason = "unresolvable"

	// ReasonEndpointInactive marks an attributed event whose owning Conta has no active
	// outbound endpoint at forward time (no config, or config disabled). It is a
	// fail-closed outcome from F2: the event is parked rather than forwarded anywhere
	// (there is nothing legitimate to forward to) and, critically, never to another
	// Conta's endpoint (A01).
	ReasonEndpointInactive Reason = "endpoint_inactive"

	// ReasonDeliveryExhausted marks an attributed event whose forward failed on every
	// bounded attempt (the endpoint kept erroring or timing out). It is F2's terminal
	// give-up: the event leaves the outbox and is parked for inspection/replay instead
	// of being retried forever (threat D1 — no infinite retry loop).
	ReasonDeliveryExhausted Reason = "delivery_exhausted"
)

// valid reports whether r is a known reason. Guards the DeadLetter constructor so a
// caller cannot persist an arbitrary/empty reason string.
func (r Reason) valid() bool {
	switch r {
	case ReasonUnresolvable, ReasonEndpointInactive, ReasonDeliveryExhausted:
		return true
	default:
		return false
	}
}

// Delivery is an inbound event durably ATTRIBUTED to its owning Conta and enqueued on
// that Conta's outbox for F2 to forward. It is immutable in F1 (created pending); the
// (accountID, eventKey) pair is the idempotency/dedup key so a redelivered inbound
// event never enqueues twice.
type Delivery struct {
	id        string
	accountID string
	tenantID  string
	eventKey  string
	txID      string
	eventType string
	status    DeliveryStatus
	createdAt time.Time
	detail    Detail
}

// Detail is the NON-PII business detail carried with a delivery so a Conta's receiver
// learns what settled without calling our API back for it: the amount in CENTS (never
// reais — minor units are the only representation that crosses this boundary, so no
// decimal rounding can ever change a value in transit), how many parcelas a card
// authorisation was split into, and the PSP's capture message.
//
// It is deliberately narrow. The outbox stays free of the devedor PII a Pix payload can
// hold (sin-68744), which is what lets these tables remain unencrypted; an installment
// count, a status message and an amount identify no natural person. A PIX or boleto
// settlement leaves the card fields zero/empty.
type Detail struct {
	AmountCents  int64
	Installments int
	Message      string
}

// NewDelivery constructs a pending Delivery, enforcing the invariants that make
// attribution safe: a non-empty id, a non-empty accountID (the SERVER-SIDE resolved
// owning Conta — an empty owner is never a Delivery, it is the caller's cue to
// DeadLetter), a non-empty tenantID and event_key (dedup), and a non-empty event type.
// txID may be empty for an event that carries no charge id. The status is always
// pending.
func NewDelivery(id, accountID, tenantID, eventKey, txID, eventType string, detail Detail, now time.Time) (*Delivery, error) {
	id = strings.TrimSpace(id)
	accountID = strings.TrimSpace(accountID)
	tenantID = strings.TrimSpace(tenantID)
	eventKey = strings.TrimSpace(eventKey)
	eventType = strings.TrimSpace(eventType)
	if id == "" {
		return nil, shared.NewValidationError("id", "delivery id is required")
	}
	if accountID == "" {
		return nil, shared.NewValidationError("account_id", "account id is required")
	}
	if tenantID == "" {
		return nil, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	if eventKey == "" {
		return nil, shared.NewValidationError("event_key", "event key is required")
	}
	if eventType == "" {
		return nil, shared.NewValidationError("event_type", "event type is required")
	}
	return &Delivery{
		id:        id,
		accountID: accountID,
		tenantID:  tenantID,
		eventKey:  eventKey,
		txID:      strings.TrimSpace(txID),
		eventType: eventType,
		status:    StatusPending,
		createdAt: now,
		detail:    detail,
	}, nil
}

// RehydrateDelivery rebuilds a Delivery from persisted state without re-running
// creation validation (persistence adapters only).
func RehydrateDelivery(id, accountID, tenantID, eventKey, txID, eventType string, status DeliveryStatus, createdAt time.Time, detail Detail) *Delivery {
	return &Delivery{
		id:        id,
		accountID: accountID,
		tenantID:  tenantID,
		eventKey:  eventKey,
		txID:      txID,
		eventType: eventType,
		status:    status,
		createdAt: createdAt,
		detail:    detail,
	}
}

// ID returns the delivery's opaque id.
func (d *Delivery) ID() string { return d.id }

// AccountID returns the owning Conta the event was attributed to (server-side).
func (d *Delivery) AccountID() string { return d.accountID }

// TenantID returns the originating tenant (the authenticated inbound channel).
func (d *Delivery) TenantID() string { return d.tenantID }

// EventKey returns the dedup key (shared with the inbound processed-events barrier).
func (d *Delivery) EventKey() string { return d.eventKey }

// TxID returns the charge/session id the event refers to (may be empty).
func (d *Delivery) TxID() string { return d.txID }

// EventType returns the business event type (e.g. payment.paid).
func (d *Delivery) EventType() string { return d.eventType }

// Status returns the lifecycle status (pending in F1).
func (d *Delivery) Status() DeliveryStatus { return d.status }

// Detail returns the non-PII business detail forwarded with this delivery.
func (d *Delivery) Detail() Detail { return d.detail }

// CreatedAt returns the attribution instant.
func (d *Delivery) CreatedAt() time.Time { return d.createdAt }

// DeadLetter is an inbound event that could NOT be attributed to a Conta, parked for
// inspection/replay. It deliberately carries NO accountID (the owner is unknown by
// definition) — only the tenant, the dedup key, the referenced txID/type and the
// reason. The (tenantID, eventKey) pair is its idempotency key.
type DeadLetter struct {
	id        string
	tenantID  string
	eventKey  string
	txID      string
	eventType string
	reason    Reason
	createdAt time.Time
}

// NewDeadLetter constructs a DeadLetter, enforcing a non-empty id/tenantID/event_key/
// event type and a KNOWN reason (an unknown or empty reason is rejected so the parked
// record is always classifiable). txID may be empty.
func NewDeadLetter(id, tenantID, eventKey, txID, eventType string, reason Reason, now time.Time) (*DeadLetter, error) {
	id = strings.TrimSpace(id)
	tenantID = strings.TrimSpace(tenantID)
	eventKey = strings.TrimSpace(eventKey)
	eventType = strings.TrimSpace(eventType)
	if id == "" {
		return nil, shared.NewValidationError("id", "dead-letter id is required")
	}
	if tenantID == "" {
		return nil, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	if eventKey == "" {
		return nil, shared.NewValidationError("event_key", "event key is required")
	}
	if eventType == "" {
		return nil, shared.NewValidationError("event_type", "event type is required")
	}
	if !reason.valid() {
		return nil, shared.NewValidationError("reason", "dead-letter reason is unknown")
	}
	return &DeadLetter{
		id:        id,
		tenantID:  tenantID,
		eventKey:  eventKey,
		txID:      strings.TrimSpace(txID),
		eventType: eventType,
		reason:    reason,
		createdAt: now,
	}, nil
}

// DeadLetterFromDelivery parks an already-attributed Delivery that F2 could not deliver
// (its endpoint is inactive, or every bounded forward attempt failed). It carries the
// Delivery's tenant/event_key/tx_id/event_type across to the park with the given F2
// reason (ReasonEndpointInactive / ReasonDeliveryExhausted). The park deliberately keeps
// NO account_id (the dead-letter table has no such column — an unattributable F1 event
// has no owner) — the owning Conta is recoverable from the audit trail and the shared
// event_key, so the park stays a single uniform shape. A non-F2 reason is rejected so a
// caller cannot mislabel a delivery failure.
func DeadLetterFromDelivery(id string, d *Delivery, reason Reason, now time.Time) (*DeadLetter, error) {
	if d == nil {
		return nil, shared.NewValidationError("delivery", "delivery is required")
	}
	if reason != ReasonEndpointInactive && reason != ReasonDeliveryExhausted {
		return nil, shared.NewValidationError("reason", "reason is not an F2 delivery-failure reason")
	}
	return NewDeadLetter(id, d.tenantID, d.eventKey, d.txID, d.eventType, reason, now)
}

// RehydrateDeadLetter rebuilds a DeadLetter from persisted state (adapters only).
func RehydrateDeadLetter(id, tenantID, eventKey, txID, eventType string, reason Reason, createdAt time.Time) *DeadLetter {
	return &DeadLetter{
		id:        id,
		tenantID:  tenantID,
		eventKey:  eventKey,
		txID:      txID,
		eventType: eventType,
		reason:    reason,
		createdAt: createdAt,
	}
}

// ID returns the dead-letter's opaque id.
func (d *DeadLetter) ID() string { return d.id }

// TenantID returns the originating tenant.
func (d *DeadLetter) TenantID() string { return d.tenantID }

// EventKey returns the dedup key.
func (d *DeadLetter) EventKey() string { return d.eventKey }

// TxID returns the referenced charge/session id (may be empty).
func (d *DeadLetter) TxID() string { return d.txID }

// EventType returns the business event type.
func (d *DeadLetter) EventType() string { return d.eventType }

// Reason returns why the event was parked.
func (d *DeadLetter) Reason() Reason { return d.reason }

// CreatedAt returns the parking instant.
func (d *DeadLetter) CreatedAt() time.Time { return d.createdAt }
