package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/pixcobv"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// PixCobVCreateEndpoint is the billable endpoint key for creating a PIX charge with
// a due date (cobv). It anchors per-tenant pricing exactly like pix.create; a tenant
// without a configured price for it cannot create a cobv charge.
const PixCobVCreateEndpoint = "pix.cobv.create"

// PixDueChargeService creates, reads and amends PIX charges with a due date
// (cobrança com vencimento, cobv — roteiro 7.5–7.7). Create mirrors PixService's
// financial-integrity ordering (idempotent reservation BEFORE the bank call, then
// tx id + ledger persisted atomically); Get is a pure reconcile read; Update amends
// an already-billed charge and never bills again. The tenant is always the
// authenticated tenant, never client input (threat H1/P1).
type PixDueChargeService struct {
	payments ports.PaymentRepository
	tenants  ports.TenantRepository
	pricing  ports.PricingRepository
	cobv     ports.PixDueChargeProvider
	bus      ports.MessageBus
	clock    ports.Clock
	ids      ports.IDProvider
	uow      ports.UnitOfWork
}

// NewPixDueChargeService wires a PixDueChargeService from the provided ports.
func NewPixDueChargeService(d Deps) *PixDueChargeService {
	return &PixDueChargeService{
		payments: d.Payments,
		tenants:  d.Tenants,
		pricing:  d.Pricing,
		cobv:     d.PixDueCharge,
		bus:      d.Bus,
		clock:    d.Clock,
		ids:      d.IDs,
		uow:      resolveUoW(d),
	}
}

// DueChargeInput is the validated boundary input for creating or amending a cobv
// charge. TenantID is the authenticated tenant. DueDate must be in the future;
// ValidityDays is the validade após vencimento; fine/interest/discount are the
// rates (validated against the legal caps in the core). The devedor and creditor
// PIX key are required.
type DueChargeInput struct {
	TenantID string
	// AccountID is the owning account resolved at the auth choke-point (SIN-69126),
	// stamped on the ledger for account→tenant→endpoint metering (SIN-69127).
	// Attribution-only; empty = self-account. See CreateChargeInput.AccountID.
	AccountID          string
	AmountCents        int64
	Currency           string
	DueDate            time.Time
	ValidityDays       int
	FineBps            int64
	MonthlyInterestBps int64
	DiscountBps        int64
	DiscountFixedCents int64
	DebtorTaxID        string
	DebtorName         string
	CreditorKey        string
	IdempotencyKey     string
}

// CreateDueCharge registers a pending cobv charge at the bank and records the
// billable event, returning the persisted payment together with the charge's QR
// material. Retrying with the same idempotency key returns the original payment
// (re-reading its charge) without billing again. Ordering mirrors PixService
// (reserve-before-bank, then tx id + ledger atomic).
func (s *PixDueChargeService) CreateDueCharge(ctx context.Context, in DueChargeInput) (*payment.Payment, ports.PixDueChargeResult, error) {
	t, err := s.tenants.FindTenantByID(ctx, in.TenantID)
	if err != nil {
		return nil, ports.PixDueChargeResult{}, fmt.Errorf("resolve tenant: %w", err)
	}
	if !t.Active() {
		return nil, ports.PixDueChargeResult{}, shared.NewValidationError("tenant", "tenant is not active")
	}
	if in.IdempotencyKey == "" {
		return nil, ports.PixDueChargeResult{}, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}

	principal, err := shared.NewMoney(in.AmountCents, in.Currency)
	if err != nil {
		return nil, ports.PixDueChargeResult{}, err
	}
	// Validate the whole cobv in the core (caps, discount, devedor, creditor key)
	// and the future-due-date boundary BEFORE reserving a payment, so an invalid
	// request never leaves a reserved-but-unusable payment behind.
	if err := s.validateDueCharge(in, principal); err != nil {
		return nil, ports.PixDueChargeResult{}, err
	}

	// Unpriced endpoint = free (bill 0), not a rejection — see resolvePriceOrFree.
	price, err := resolvePriceOrFree(ctx, s.pricing, in.TenantID, PixCobVCreateEndpoint)
	if err != nil {
		return nil, ports.PixDueChargeResult{}, err
	}

	p, err := s.reservePayment(ctx, in.TenantID, in.IdempotencyKey, principal)
	if err != nil {
		return nil, ports.PixDueChargeResult{}, err
	}
	if p.TxID() != "" {
		// Already created and billed by a prior request with this key: re-read the
		// authoritative state so the caller gets a consistent response.
		res, err := s.cobv.GetDueCharge(ctx, in.TenantID, p.TxID())
		if err != nil {
			return nil, ports.PixDueChargeResult{}, fmt.Errorf("reconcile existing cobv charge: %w", err)
		}
		return p, res, nil
	}

	res, err := s.cobv.CreateDueCharge(ctx, in.TenantID, s.toRequest(in, ""))
	if err != nil {
		return nil, ports.PixDueChargeResult{}, fmt.Errorf("bank create cobv charge: %w", err)
	}
	p.SetTxID(res.TxID)

	entry, err := billing.NewLedgerEntry(s.ids.NewID(), in.TenantID, PixCobVCreateEndpoint, p.ID(), price.PriceCents(), s.clock.Now(), billing.WithAccount(in.AccountID))
	if err != nil {
		return nil, ports.PixDueChargeResult{}, err
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
		return nil, ports.PixDueChargeResult{}, err
	}

	if finalized {
		s.publishEvent(ctx, TopicPaymentCreated, p)
	}
	return p, res, nil
}

// GetDueCharge reconciles the authoritative state of a cobv charge from the bank for
// the authenticated tenant (roteiro 7.6). An unknown txid surfaces as not-found (no
// cross-tenant disclosure: the bank read is tenant-scoped).
func (s *PixDueChargeService) GetDueCharge(ctx context.Context, tenantID, txID string) (ports.PixDueChargeResult, error) {
	txID = strings.TrimSpace(txID)
	if txID == "" {
		return ports.PixDueChargeResult{}, shared.NewValidationError("txid", "txid is required")
	}
	return s.cobv.GetDueCharge(ctx, tenantID, txID)
}

// UpdateDueCharge amends a registered cobv's parameters for the authenticated tenant
// (roteiro 7.7). The full new parameter set is validated in the core before it
// reaches the bank; the amendment is idempotent on the forwarded key. It does not
// bill again (the charge was billed at creation). An unknown txid surfaces as
// not-found (tenant-scoped: no cross-tenant amend).
func (s *PixDueChargeService) UpdateDueCharge(ctx context.Context, tenantID, txID string, in DueChargeInput) (ports.PixDueChargeResult, error) {
	txID = strings.TrimSpace(txID)
	if txID == "" {
		return ports.PixDueChargeResult{}, shared.NewValidationError("txid", "txid is required")
	}
	if in.IdempotencyKey == "" {
		return ports.PixDueChargeResult{}, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	principal, err := shared.NewMoney(in.AmountCents, in.Currency)
	if err != nil {
		return ports.PixDueChargeResult{}, err
	}
	if err := s.validateDueCharge(in, principal); err != nil {
		return ports.PixDueChargeResult{}, err
	}
	return s.cobv.UpdateDueCharge(ctx, tenantID, txID, s.toRequest(in, txID))
}

// validateDueCharge runs the pure-domain invariants (pixcobv.New) plus the
// clock-dependent future-due-date boundary check. in.TenantID is used so the domain
// can enforce its tenant invariant; the result is discarded (the canonical charge is
// rebuilt by the adapter from the transported parameters).
func (s *PixDueChargeService) validateDueCharge(in DueChargeInput, principal shared.Money) error {
	if !dayAfter(in.DueDate, s.clock.Now()) {
		return shared.NewValidationError("due_date", "due date must be in the future")
	}
	_, err := pixcobv.New(pixcobv.Params{
		TenantID:           in.TenantID,
		Principal:          principal,
		DueDate:            in.DueDate,
		ValidityDays:       in.ValidityDays,
		FineBps:            in.FineBps,
		MonthlyInterestBps: in.MonthlyInterestBps,
		DiscountBps:        in.DiscountBps,
		DiscountFixedCents: in.DiscountFixedCents,
		DebtorTaxID:        in.DebtorTaxID,
		DebtorName:         in.DebtorName,
		CreditorKey:        in.CreditorKey,
	})
	return err
}

// toRequest maps the validated input to the PSP port request. txID is empty on
// create (the adapter derives it from the idempotency anchor) and the known txid on
// amend.
func (s *PixDueChargeService) toRequest(in DueChargeInput, txID string) ports.PixDueChargeRequest {
	return ports.PixDueChargeRequest{
		TenantID:           in.TenantID,
		TxID:               txID,
		AmountCents:        in.AmountCents,
		Currency:           in.Currency,
		DueDate:            in.DueDate,
		ValidityDays:       in.ValidityDays,
		FineBps:            in.FineBps,
		MonthlyInterestBps: in.MonthlyInterestBps,
		DiscountBps:        in.DiscountBps,
		DiscountFixedCents: in.DiscountFixedCents,
		DebtorTaxID:        in.DebtorTaxID,
		DebtorName:         in.DebtorName,
		CreditorKey:        in.CreditorKey,
		IdempotencyKey:     in.IdempotencyKey,
	}
}

// reservePayment returns the payment to bill for this cobv: an existing one for the
// idempotency key (resumed), or a freshly persisted pending payment reserving the
// key. On a uniqueness race the winner is returned (no double bill). Mirrors
// PixService.reservePayment for the cobv endpoint.
func (s *PixDueChargeService) reservePayment(ctx context.Context, tenantID, idemKey string, amount shared.Money) (*payment.Payment, error) {
	existing, err := s.payments.FindPaymentByIdempotencyKey(ctx, tenantID, idemKey)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("idempotency lookup: %w", err)
	}

	p, err := payment.New(s.ids.NewID(), tenantID, PixCobVCreateEndpoint, idemKey, amount, s.clock.Now())
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
		won, lookupErr := s.payments.FindPaymentByIdempotencyKey(ctx, tenantID, idemKey)
		if lookupErr != nil {
			return nil, fmt.Errorf("resolve idempotency conflict: %w", lookupErr)
		}
		return won, nil
	}
	return nil, fmt.Errorf("reserve payment: %w", err)
}

// dayAfter reports whether t falls on a calendar day strictly after ref's day, in
// ref's location. A cobv due date must be in the future (after today) — same-day is
// rejected so a charge always has a real vencimento window.
func dayAfter(t, ref time.Time) bool {
	day := func(x time.Time) time.Time {
		y, m, d := x.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, ref.Location())
	}
	return day(t).After(day(ref))
}

// publishEvent best-effort publishes a payment lifecycle event. A publish failure
// must never fail the persisted charge.
func (s *PixDueChargeService) publishEvent(ctx context.Context, topic string, p *payment.Payment) {
	payload, err := json.Marshal(struct {
		PaymentID string `json:"payment_id"`
		TenantID  string `json:"tenant_id"`
		Status    string `json:"status"`
		TxID      string `json:"tx_id"`
	}{p.ID(), p.TenantID(), string(p.Status()), p.TxID()})
	if err != nil {
		return
	}
	_ = s.bus.Publish(ctx, topic, ports.Message{
		TenantID:       p.TenantID(),
		Type:           topic,
		IdempotencyKey: p.IdempotencyKey(),
		Payload:        payload,
	})
}
