package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// ChargeService creates and reads charges. It enforces idempotency (no double
// charge on retry), tenant scoping (no IDOR), and per-endpoint billing.
type ChargeService struct {
	payments ports.PaymentRepository
	tenants  ports.TenantRepository
	pricing  ports.PricingRepository
	bank     ports.BankProvider
	bus      ports.MessageBus
	clock    ports.Clock
	ids      ports.IDProvider
	uow      ports.UnitOfWork
}

// NewChargeService wires a ChargeService from the provided ports.
func NewChargeService(d Deps) *ChargeService {
	return &ChargeService{
		payments: d.Payments,
		tenants:  d.Tenants,
		pricing:  d.Pricing,
		bank:     d.Bank,
		bus:      d.Bus,
		clock:    d.Clock,
		ids:      d.IDs,
		uow:      resolveUoW(d),
	}
}

// CreateChargeInput is the validated boundary input for creating a charge. The
// TenantID is the authenticated tenant, never a client-supplied field.
type CreateChargeInput struct {
	TenantID string
	// AccountID is the owning API-user/reseller account resolved at the auth
	// choke-point (Principal.AccountID, SIN-69126). Attribution-only: it is stamped
	// on the ledger entry for account→tenant→endpoint metering (SIN-69127) and never
	// affects routing or authorization. Empty = the tenant's self-account.
	AccountID      string
	Endpoint       string
	AmountCents    int64
	Currency       string
	IdempotencyKey string
}

// CreateCharge creates a pending charge at the bank and records the billable
// event. Retrying with the same idempotency key returns the original payment
// without charging again.
//
// Ordering is chosen for financial integrity (SIN-64719):
//   - F3a: the idempotency key is reserved (a pending payment is persisted, with
//     the unique index serializing concurrent requests) BEFORE the bank is
//     charged. Two racing requests with the same key resolve to a single charge:
//     the loser sees ErrConflict on reservation and returns the winner's payment.
//   - F1: the bank tx id and the billable ledger entry are persisted together in
//     one transaction, so a ledger failure can never leave a charged-but-unbilled
//     payment. A reservation that never reached this atomic finalize (no tx id
//     persisted) is resumed on the next attempt rather than returned half-done —
//     the billable event is never silently dropped.
func (s *ChargeService) CreateCharge(ctx context.Context, in CreateChargeInput) (*payment.Payment, error) {
	t, err := s.tenants.FindTenantByID(ctx, in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}
	if !t.Active() {
		return nil, shared.NewValidationError("tenant", "tenant is not active")
	}

	if in.IdempotencyKey == "" {
		return nil, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}

	// Resolve per-endpoint price (config error if the endpoint isn't priced).
	price, err := s.pricing.GetEndpointPrice(ctx, in.TenantID, in.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("resolve price: %w", err)
	}

	// Idempotency: a prior request with the same key either completed (has a tx
	// id → return it) or only reserved the key before failing mid-flight (no tx id
	// → resume it). A miss reserves a fresh pending payment.
	p, err := s.reservePayment(ctx, in)
	if err != nil {
		return nil, err
	}
	if p.TxID() != "" {
		return p, nil // already created and billed
	}

	res, err := s.bank.CreateCharge(ctx, in.TenantID, ports.ChargeRequest{
		TenantID:    in.TenantID,
		PaymentID:   p.ID(),
		AmountCents: p.Amount().Cents(),
		Currency:    p.Amount().Currency(),
		// F3b: forward the idempotency key so the bank/PSP deduplicates the charge
		// on retry/concurrency, even if the local reservation could not collapse it.
		IdempotencyKey: in.IdempotencyKey,
	})
	if err != nil {
		return nil, fmt.Errorf("bank create charge: %w", err)
	}
	p.SetTxID(res.TxID)

	// F1: persist the tx id and the billable ledger entry atomically. The finalize
	// is also idempotent — a concurrent attempt that resumed the same reservation
	// (or an earlier crash/retry) must not append the ledger twice. We re-read the
	// payment inside the tx: if it already carries a tx id it was finalized and
	// billed, so we adopt it and skip the second append.
	entry, err := billing.NewLedgerEntry(s.ids.NewID(), in.TenantID, in.Endpoint, p.ID(), price.PriceCents(), s.clock.Now(), billing.WithAccount(in.AccountID))
	if err != nil {
		return nil, err
	}
	finalized := false
	if err := s.uow.WithinTx(ctx, func(r ports.Repository) error {
		current, lookupErr := r.FindPaymentByIdempotencyKey(ctx, in.TenantID, in.IdempotencyKey)
		if lookupErr == nil && current.TxID() != "" {
			p = current // already finalized and billed by a concurrent/earlier attempt
			return nil
		}
		if lookupErr != nil && !errors.Is(lookupErr, shared.ErrNotFound) {
			return fmt.Errorf("reload payment: %w", lookupErr)
		}
		if err := r.SavePayment(ctx, p); err != nil {
			return fmt.Errorf("save payment: %w", err)
		}
		if err := r.AppendLedgerEntry(ctx, entry); err != nil {
			return fmt.Errorf("append ledger: %w", err)
		}
		finalized = true
		return nil
	}); err != nil {
		return nil, err
	}

	if finalized {
		s.publishPaymentEvent(ctx, TopicPaymentCreated, p)
	}
	return p, nil
}

// reservePayment returns the payment to charge for this request. If a payment
// already exists for the idempotency key it is returned (completed or to be
// resumed); otherwise a fresh pending payment is persisted to reserve the key.
// On a uniqueness race the existing payment is returned (F3a — no double charge).
func (s *ChargeService) reservePayment(ctx context.Context, in CreateChargeInput) (*payment.Payment, error) {
	existing, err := s.payments.FindPaymentByIdempotencyKey(ctx, in.TenantID, in.IdempotencyKey)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("idempotency lookup: %w", err)
	}

	amount, err := shared.NewMoney(in.AmountCents, in.Currency)
	if err != nil {
		return nil, err
	}
	p, err := payment.New(s.ids.NewID(), in.TenantID, in.Endpoint, in.IdempotencyKey, amount, s.clock.Now())
	if err != nil {
		return nil, err
	}

	err = s.uow.WithinTx(ctx, func(r ports.Repository) error {
		return r.SavePayment(ctx, p)
	})
	if err == nil {
		return p, nil
	}
	if errors.Is(err, shared.ErrConflict) {
		// A concurrent request won the reservation: return its payment.
		won, lookupErr := s.payments.FindPaymentByIdempotencyKey(ctx, in.TenantID, in.IdempotencyKey)
		if lookupErr != nil {
			return nil, fmt.Errorf("resolve idempotency conflict: %w", lookupErr)
		}
		return won, nil
	}
	return nil, fmt.Errorf("reserve payment: %w", err)
}

// GetPayment returns a payment scoped to the authenticated tenant. A payment
// owned by another tenant surfaces as not-found (no cross-tenant disclosure).
func (s *ChargeService) GetPayment(ctx context.Context, tenantID, id string) (*payment.Payment, error) {
	p, err := s.payments.FindPaymentByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if p.TenantID() != tenantID {
		// Defense in depth: the repository already scopes by tenant.
		return nil, shared.ErrNotFound
	}
	return p, nil
}

func (s *ChargeService) publishPaymentEvent(ctx context.Context, topic string, p *payment.Payment) {
	payload, err := json.Marshal(struct {
		PaymentID string `json:"payment_id"`
		TenantID  string `json:"tenant_id"`
		Status    string `json:"status"`
		TxID      string `json:"tx_id"`
	}{p.ID(), p.TenantID(), string(p.Status()), p.TxID()})
	if err != nil {
		return
	}
	// Best-effort publish; failure to publish must not fail the persisted charge.
	_ = s.bus.Publish(ctx, topic, ports.Message{
		TenantID:       p.TenantID(),
		Type:           topic,
		IdempotencyKey: p.IdempotencyKey(),
		Payload:        payload,
	})
}
