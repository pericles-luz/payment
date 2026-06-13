// Package payment holds the Payment aggregate. A payment is always owned by a
// single tenant; the tenant boundary is an invariant enforced here and never
// derived from client-supplied input. Pure domain — no infra imports.
package payment

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// Status is the lifecycle state of a payment.
type Status string

const (
	// StatusPending — charge created at the bank, awaiting settlement.
	StatusPending Status = "pending"
	// StatusPaid — settlement confirmed (only via reconciliation, never trusting a raw webhook).
	StatusPaid Status = "paid"
	// StatusCanceled — charge canceled before settlement.
	StatusCanceled Status = "canceled"
)

// Payment is the aggregate root for a single charge.
type Payment struct {
	id             string
	tenantID       string
	amount         shared.Money
	status         Status
	endpoint       string
	idempotencyKey string
	txID           string
	createdAt      time.Time
	updatedAt      time.Time
}

// New constructs a pending Payment, enforcing all invariants. tenantID and
// idempotencyKey are mandatory; the amount must be positive (validated by Money).
func New(id, tenantID, endpoint, idempotencyKey string, amount shared.Money, now time.Time) (*Payment, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, shared.NewValidationError("id", "payment id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, shared.NewValidationError("endpoint", "endpoint is required")
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		return nil, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	if amount.IsZero() {
		return nil, shared.NewValidationError("amount", "amount is required")
	}
	return &Payment{
		id:             id,
		tenantID:       tenantID,
		amount:         amount,
		status:         StatusPending,
		endpoint:       endpoint,
		idempotencyKey: idempotencyKey,
		createdAt:      now,
		updatedAt:      now,
	}, nil
}

// Rehydrate rebuilds a Payment from persisted state (used by persistence adapters).
func Rehydrate(id, tenantID, endpoint, idempotencyKey, txID string, amount shared.Money, status Status, createdAt, updatedAt time.Time) *Payment {
	return &Payment{
		id:             id,
		tenantID:       tenantID,
		amount:         amount,
		status:         status,
		endpoint:       endpoint,
		idempotencyKey: idempotencyKey,
		txID:           txID,
		createdAt:      createdAt,
		updatedAt:      updatedAt,
	}
}

// MarkPaid transitions a pending payment to paid and records the bank txID.
// Only pending payments may be settled; re-settling an already-paid payment with
// the same txID is idempotent (no error), any other transition is rejected.
func (p *Payment) MarkPaid(txID string, now time.Time) error {
	txID = strings.TrimSpace(txID)
	if txID == "" {
		return shared.NewValidationError("tx_id", "tx id is required to settle")
	}
	if p.status == StatusPaid {
		if p.txID == txID {
			return nil // idempotent replay
		}
		return shared.ErrConflict
	}
	if p.status != StatusPending {
		return shared.ErrInvalidTransition
	}
	p.status = StatusPaid
	p.txID = txID
	p.updatedAt = now
	return nil
}

// Cancel transitions a pending payment to canceled.
func (p *Payment) Cancel(now time.Time) error {
	if p.status != StatusPending {
		return shared.ErrInvalidTransition
	}
	p.status = StatusCanceled
	p.updatedAt = now
	return nil
}

// SetTxID records the bank transaction id assigned at charge creation time.
func (p *Payment) SetTxID(txID string) { p.txID = strings.TrimSpace(txID) }

// Getters (no setters — the aggregate guards its own state).

// ID returns the payment identifier.
func (p *Payment) ID() string { return p.id }

// TenantID returns the owning tenant. Used for scope checks.
func (p *Payment) TenantID() string { return p.tenantID }

// Amount returns the monetary amount.
func (p *Payment) Amount() shared.Money { return p.amount }

// Status returns the current lifecycle state.
func (p *Payment) Status() Status { return p.status }

// Endpoint returns the billable endpoint that produced this payment.
func (p *Payment) Endpoint() string { return p.endpoint }

// IdempotencyKey returns the client-supplied idempotency key.
func (p *Payment) IdempotencyKey() string { return p.idempotencyKey }

// TxID returns the bank transaction id (empty until assigned).
func (p *Payment) TxID() string { return p.txID }

// CreatedAt returns the creation timestamp.
func (p *Payment) CreatedAt() time.Time { return p.createdAt }

// UpdatedAt returns the last-update timestamp.
func (p *Payment) UpdatedAt() time.Time { return p.updatedAt }
