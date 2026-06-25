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
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// PixCreateEndpoint is the billable endpoint key for creating an immediate PIX
// charge. It anchors per-tenant pricing/billing exactly like the generic charge
// endpoints; a tenant without a configured price for it cannot create a charge.
const PixCreateEndpoint = "pix.create"

// maxPixListRange bounds the listing date window so an unbounded interval cannot be
// pushed to the PSP. A year comfortably covers any homologação/reconciliation pull.
const maxPixListRange = 366 * 24 * time.Hour

// PixService creates and reads immediate PIX charges (cobrança imediata,
// homologação roteiro 7.1–7.4). Create mirrors ChargeService's financial-integrity
// ordering (idempotent reservation BEFORE the bank call, then tx id + ledger
// persisted atomically); Get and List are pure reconcile reads against the PSP. The
// tenant is always the authenticated tenant, never client input (threat H1/P1).
type PixService struct {
	payments ports.PaymentRepository
	tenants  ports.TenantRepository
	pricing  ports.PricingRepository
	pix      ports.PixProvider
	bus      ports.MessageBus
	clock    ports.Clock
	ids      ports.IDProvider
	uow      ports.UnitOfWork
}

// NewPixService wires a PixService from the provided ports.
func NewPixService(d Deps) *PixService {
	return &PixService{
		payments: d.Payments,
		tenants:  d.Tenants,
		pricing:  d.Pricing,
		pix:      d.Pix,
		bus:      d.Bus,
		clock:    d.Clock,
		ids:      d.IDs,
		uow:      resolveUoW(d),
	}
}

// CreateImmediateChargeInput is the validated boundary input for creating an
// immediate PIX charge. TenantID is the authenticated tenant. Devedor (DebtorTaxID
// + DebtorName) is optional (roteiro 7.2).
type CreateImmediateChargeInput struct {
	TenantID         string
	AmountCents      int64
	Currency         string
	IdempotencyKey   string
	ExpiresInSeconds int64
	DebtorTaxID      string
	DebtorName       string
}

// CreateImmediateCharge creates a pending immediate PIX charge at the bank and
// records the billable event, returning the persisted payment together with the
// charge's QR material/expiry. Retrying with the same idempotency key returns the
// original payment (and re-reads its QR) without charging again.
//
// Ordering mirrors ChargeService (SIN-64719): the idempotency key is reserved
// (pending payment persisted, unique index serialising racers) BEFORE the bank is
// charged, then the bank tx id and the ledger entry are persisted together in one
// transaction so a ledger failure can never leave a charged-but-unbilled payment.
func (s *PixService) CreateImmediateCharge(ctx context.Context, in CreateImmediateChargeInput) (*payment.Payment, ports.PixChargeResult, error) {
	t, err := s.tenants.FindTenantByID(ctx, in.TenantID)
	if err != nil {
		return nil, ports.PixChargeResult{}, fmt.Errorf("resolve tenant: %w", err)
	}
	if !t.Active() {
		return nil, ports.PixChargeResult{}, shared.NewValidationError("tenant", "tenant is not active")
	}
	if in.IdempotencyKey == "" {
		return nil, ports.PixChargeResult{}, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	if in.ExpiresInSeconds < 0 {
		return nil, ports.PixChargeResult{}, shared.NewValidationError("expires_in_seconds", "must not be negative")
	}
	if err := validateDebtor(in.DebtorTaxID, in.DebtorName); err != nil {
		return nil, ports.PixChargeResult{}, err
	}

	price, err := s.pricing.GetEndpointPrice(ctx, in.TenantID, PixCreateEndpoint)
	if err != nil {
		return nil, ports.PixChargeResult{}, fmt.Errorf("resolve price: %w", err)
	}

	p, err := s.reservePayment(ctx, in)
	if err != nil {
		return nil, ports.PixChargeResult{}, err
	}
	if p.TxID() != "" {
		// Already created and billed by a prior request with this key: re-read the
		// authoritative QR/state so the caller gets a consistent response.
		qr, err := s.pix.GetImmediateCharge(ctx, in.TenantID, p.TxID())
		if err != nil {
			return nil, ports.PixChargeResult{}, fmt.Errorf("reconcile existing pix charge: %w", err)
		}
		return p, qr, nil
	}

	qr, err := s.pix.CreateImmediateCharge(ctx, in.TenantID, ports.ChargeRequest{
		TenantID:       in.TenantID,
		PaymentID:      p.ID(),
		AmountCents:    p.Amount().Cents(),
		Currency:       p.Amount().Currency(),
		IdempotencyKey: in.IdempotencyKey,
		DebtorTaxID:    strings.TrimSpace(in.DebtorTaxID),
		DebtorName:     strings.TrimSpace(in.DebtorName),
	}, time.Duration(in.ExpiresInSeconds)*time.Second)
	if err != nil {
		return nil, ports.PixChargeResult{}, fmt.Errorf("bank create pix charge: %w", err)
	}
	p.SetTxID(qr.TxID)

	entry, err := billing.NewLedgerEntry(s.ids.NewID(), in.TenantID, PixCreateEndpoint, p.ID(), price.PriceCents(), s.clock.Now())
	if err != nil {
		return nil, ports.PixChargeResult{}, err
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
		return nil, ports.PixChargeResult{}, err
	}

	if finalized {
		s.publishPaymentEvent(ctx, TopicPaymentCreated, p)
	}
	return p, qr, nil
}

// reservePayment returns the payment to charge for this request: an existing one
// for the idempotency key (returned to be completed/resumed), or a freshly persisted
// pending payment reserving the key. On a uniqueness race the winner is returned
// (no double charge). It mirrors ChargeService.reservePayment for the PIX endpoint.
func (s *PixService) reservePayment(ctx context.Context, in CreateImmediateChargeInput) (*payment.Payment, error) {
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
	p, err := payment.New(s.ids.NewID(), in.TenantID, PixCreateEndpoint, in.IdempotencyKey, amount, s.clock.Now())
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
		won, lookupErr := s.payments.FindPaymentByIdempotencyKey(ctx, in.TenantID, in.IdempotencyKey)
		if lookupErr != nil {
			return nil, fmt.Errorf("resolve idempotency conflict: %w", lookupErr)
		}
		return won, nil
	}
	return nil, fmt.Errorf("reserve payment: %w", err)
}

// GetImmediateCharge reconciles the authoritative state of a PIX charge from the
// bank for the authenticated tenant (roteiro 7.3). An unknown txid surfaces as
// not-found (no cross-tenant disclosure: the bank read is tenant-scoped).
func (s *PixService) GetImmediateCharge(ctx context.Context, tenantID, txID string) (ports.PixChargeResult, error) {
	txID = strings.TrimSpace(txID)
	if txID == "" {
		return ports.PixChargeResult{}, shared.NewValidationError("txid", "txid is required")
	}
	return s.pix.GetImmediateCharge(ctx, tenantID, txID)
}

// ListImmediateChargesInput is the validated boundary input for listing immediate
// PIX charges by date window (roteiro 7.4). Page/PageSize are optional.
type ListImmediateChargesInput struct {
	TenantID string
	Start    time.Time
	End      time.Time
	Page     int
	PageSize int
}

// ListImmediateCharges lists the tenant's immediate PIX charges within the date
// window. The window is mandatory and bounded (end after start, range <=
// maxPixListRange); pagination must be non-negative.
func (s *PixService) ListImmediateCharges(ctx context.Context, in ListImmediateChargesInput) (ports.PixChargeList, error) {
	if err := validatePixListWindow(in.Start, in.End, in.Page, in.PageSize); err != nil {
		return ports.PixChargeList{}, err
	}
	return s.pix.ListImmediateCharges(ctx, in.TenantID, ports.PixListFilter{
		Start:    in.Start,
		End:      in.End,
		Page:     in.Page,
		PageSize: in.PageSize,
	})
}

// validateDebtor enforces the optional devedor block (roteiro 7.2): the devedor may
// be omitted entirely, but when present the tax id must be a syntactically valid
// CPF (11) or CNPJ (14). A name alone (no tax id) is rejected — a payer without a
// document is not a valid BACEN devedor.
func validateDebtor(taxID, name string) error {
	taxID = strings.TrimSpace(taxID)
	name = strings.TrimSpace(name)
	if taxID == "" && name == "" {
		return nil
	}
	if !validTaxID(taxID) {
		return shared.NewValidationError("devedor.tax_id", "debtor tax id must be 11 (CPF) or 14 (CNPJ) digits")
	}
	return nil
}

// validTaxID reports whether s is an all-digit CPF (11) or CNPJ (14). It is a
// syntactic check (length + digits), not a check-digit validation — mirrors the
// consent domain's guard at the PIX boundary.
func validTaxID(s string) bool {
	if len(s) != 11 && len(s) != 14 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validatePixListWindow enforces the listing constraints for the immediate PIX list
// endpoint (roteiro 7.4): a mandatory, ordered, bounded date window and non-negative
// pagination.
func validatePixListWindow(start, end time.Time, page, pageSize int) error {
	if start.IsZero() || end.IsZero() {
		return shared.NewValidationError("start_end", "start and end are required")
	}
	if !end.After(start) {
		return shared.NewValidationError("end", "end must be after start")
	}
	if end.Sub(start) > maxPixListRange {
		return shared.NewValidationError("range", "date range too large")
	}
	if page < 0 || pageSize < 0 {
		return shared.NewValidationError("pagination", "page and page_size must not be negative")
	}
	return nil
}

// publishPaymentEvent best-effort publishes a payment lifecycle event. A publish
// failure must never fail the persisted charge.
func (s *PixService) publishPaymentEvent(ctx context.Context, topic string, p *payment.Payment) {
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
