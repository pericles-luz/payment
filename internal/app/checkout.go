package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/checkout"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// CheckoutCreateEndpoint is the billable endpoint key for opening a unified hosted
// checkout session. It anchors per-tenant pricing exactly like pix.create; a tenant
// without a configured price for it cannot open a session.
const CheckoutCreateEndpoint = "checkout.create"

// MinCheckoutTotalCents is the PSP's hosted-checkout minimum, R$ 5,00 — confirmed on
// the wire on 2026-08-19: a create for R$ 3,00 answers 400 with
// "[Path '/amount'] Numeric instance is lower than the required minimum (minimum: 5)".
//
// Enforced here so a client learns the rule as a validation error instead of an
// opaque PSP failure mid-checkout, and so the tenant is not billed for a call that
// could never succeed.
const MinCheckoutTotalCents int64 = 500

// maxCheckoutItems bounds the line-item count so a single request cannot push an
// unbounded list to the PSP (defense-in-depth with the HTTP body cap).
const maxCheckoutItems = 100

// CheckoutService opens unified hosted checkout sessions (roteiro 9.a–9.c). Create
// mirrors PixService/ChargeService financial-integrity ordering: the idempotency key
// is reserved (pending payment for the session total persisted, unique index
// serialising racers) BEFORE the PSP is called, then the bank session id and the
// ledger (billing) entry are persisted atomically. The tenant is always the
// authenticated tenant, never client input.
type CheckoutService struct {
	payments ports.PaymentRepository
	tenants  ports.TenantRepository
	pricing  ports.PricingRepository
	checkout ports.CheckoutProvider
	bus      ports.MessageBus
	clock    ports.Clock
	ids      ports.IDProvider
	uow      ports.UnitOfWork
}

// NewCheckoutService wires a CheckoutService from the provided ports.
func NewCheckoutService(d Deps) *CheckoutService {
	return &CheckoutService{
		payments: d.Payments,
		tenants:  d.Tenants,
		pricing:  d.Pricing,
		checkout: d.Checkout,
		bus:      d.Bus,
		clock:    d.Clock,
		ids:      d.IDs,
		uow:      resolveUoW(d),
	}
}

// CheckoutItemInput is one validated line of a checkout request at the boundary.
type CheckoutItemInput struct {
	Description string
	AmountCents int64
}

// CreateCheckoutSessionInput is the validated boundary input for opening a checkout
// session. Expiry may be given as an absolute ExpiresAt (preferred) or a relative
// ExpiresInSeconds; one of them is required. CardType is "credit"|"debit";
// RequireAuthentication asks the hosted page to authenticate the payer (roteiro 9.c).
type CreateCheckoutSessionInput struct {
	TenantID string
	// AccountID is the owning account resolved at the auth choke-point (SIN-69126),
	// stamped on the ledger for account→tenant→endpoint metering (SIN-69127).
	// Attribution-only; empty = self-account. See CreateChargeInput.AccountID.
	AccountID             string
	Currency              string
	Items                 []CheckoutItemInput
	ExpiresAt             time.Time
	ExpiresInSeconds      int64
	CardType              string
	RequireAuthentication bool
	// MaxInstallments is the ceiling of parcelas offered to the buyer on a credit
	// purchase. Zero means a single payment.
	MaxInstallments int
	IdempotencyKey  string
}

// CreateSession opens a hosted checkout session at the bank and records the billable
// event, returning the persisted payment (reserving the session total) together with
// the bank's redirect URL / session id. Retrying with the same idempotency key
// returns the original session (the PSP collapses the retry via the forwarded key)
// without billing again.
func (s *CheckoutService) CreateSession(ctx context.Context, in CreateCheckoutSessionInput) (*payment.Payment, ports.CheckoutResult, error) {
	t, err := s.tenants.FindTenantByID(ctx, in.TenantID)
	if err != nil {
		return nil, ports.CheckoutResult{}, fmt.Errorf("resolve tenant: %w", err)
	}
	if !t.Active() {
		return nil, ports.CheckoutResult{}, shared.NewValidationError("tenant", "tenant is not active")
	}
	if in.IdempotencyKey == "" {
		return nil, ports.CheckoutResult{}, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}

	card, err := checkout.ParseCardType(in.CardType)
	if err != nil {
		return nil, ports.CheckoutResult{}, err
	}

	// Validado ANTES de reservar o pagamento: WithCard só roda depois da reserva, e
	// falhar lá deixaria uma linha de pagamento órfã e uma cobrança de tarifa por uma
	// sessão que nunca existiu.
	maxInstallments, err := checkout.NormalizeInstallments(card, in.MaxInstallments)
	if err != nil {
		return nil, ports.CheckoutResult{}, err
	}

	expiresAt, err := s.resolveExpiry(in)
	if err != nil {
		return nil, ports.CheckoutResult{}, err
	}

	items, err := buildCheckoutItems(in.Items)
	if err != nil {
		return nil, ports.CheckoutResult{}, err
	}

	// Unpriced endpoint = free (bill 0), not a rejection — see resolvePriceOrFree.
	price, err := resolvePriceOrFree(ctx, s.pricing, in.TenantID, CheckoutCreateEndpoint)
	if err != nil {
		return nil, ports.CheckoutResult{}, err
	}

	// Reserve the idempotency key (and the session total) before the PSP call. The
	// payment id doubles as the stable session id so a retry rebuilds the same id and
	// the PSP collapses it.
	var sum int64
	for _, it := range items {
		var addErr error
		if sum, addErr = shared.AddCents(sum, it.AmountCents()); addErr != nil {
			return nil, ports.CheckoutResult{}, addErr
		}
	}
	// O C6 recusa abaixo de R$ 5,00 com 400 nomeando /amount (verificado no fio em
	// 2026-08-19). Recusar aqui evita a chamada, evita cobrar a tarifa e devolve o
	// erro antes de o comprador estar no meio de um checkout.
	if sum < MinCheckoutTotalCents {
		return nil, ports.CheckoutResult{}, shared.NewValidationError("items",
			"checkout total must be at least 500 cents")
	}
	// O teto pedido é reduzido ao que o valor comporta: cada parcela precisa passar
	// do mínimo do PSP. Não é recusa — é oferecer o que o comprador pode de fato
	// aceitar. Uma compra de R$ 15,00 com teto de 6x vira 3x.
	maxInstallments = checkout.AffordableInstallments(sum, maxInstallments)

	total, err := shared.NewMoney(sum, in.Currency)
	if err != nil {
		return nil, ports.CheckoutResult{}, err
	}
	p, err := s.reservePayment(ctx, in.TenantID, in.IdempotencyKey, total)
	if err != nil {
		return nil, ports.CheckoutResult{}, err
	}

	// Build the canonical domain session (validates id/items/total/expiry/currency +
	// card type) and map it to the PSP request.
	sess, err := checkout.New(p.ID(), in.TenantID, in.Currency, items, expiresAt)
	if err != nil {
		return nil, ports.CheckoutResult{}, err
	}
	sess, err = sess.WithCard(card, in.RequireAuthentication, maxInstallments)
	if err != nil {
		return nil, ports.CheckoutResult{}, err
	}

	res, err := s.checkout.CreateCheckoutSession(ctx, in.TenantID, toCheckoutRequest(sess, in.IdempotencyKey))
	if err != nil {
		return nil, ports.CheckoutResult{}, fmt.Errorf("bank create checkout: %w", err)
	}

	if p.TxID() != "" {
		// Already opened and billed by a prior request with this key: return the
		// (idempotent) PSP result without billing again.
		return p, res, nil
	}
	p.SetTxID(res.SessionID)

	entry, err := billing.NewLedgerEntry(s.ids.NewID(), in.TenantID, CheckoutCreateEndpoint, p.ID(), price.PriceCents(), s.clock.Now(), billing.WithAccount(in.AccountID))
	if err != nil {
		return nil, ports.CheckoutResult{}, err
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
		return nil, ports.CheckoutResult{}, err
	}

	if finalized {
		s.publishPaymentEvent(ctx, TopicPaymentCreated, p)
	}
	return p, res, nil
}

// GetSession reconciles the authoritative state of a checkout session from the bank
// for the authenticated tenant (roteiro 10). The tenant is always the authenticated
// tenant (never client input); the bank read is tenant-scoped, so an id owned by
// another tenant — like an unknown id — surfaces as not-found, never disclosing
// cross-tenant existence.
func (s *CheckoutService) GetSession(ctx context.Context, tenantID, sessionID string) (ports.CheckoutResult, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ports.CheckoutResult{}, shared.NewValidationError("session_id", "session id is required")
	}
	return s.checkout.GetCheckoutSession(ctx, tenantID, sessionID)
}

// CancelSession cancels a checkout session at the bank for the authenticated tenant
// (roteiro 11). Cancelling is a write but idempotent: cancelling an already-cancelled
// session returns the cancelled state without error. An id owned by another tenant or
// an unknown id surfaces as not-found, so a cancel can never confirm a session's
// existence across tenants.
func (s *CheckoutService) CancelSession(ctx context.Context, tenantID, sessionID string) (ports.CheckoutResult, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ports.CheckoutResult{}, shared.NewValidationError("session_id", "session id is required")
	}
	return s.checkout.CancelCheckoutSession(ctx, tenantID, sessionID)
}

// resolveExpiry turns the input's absolute/relative expiry into an absolute instant
// that must lie in the future. ExpiresAt wins when both are set; otherwise a positive
// ExpiresInSeconds is applied to the clock. A missing/past expiry is a validation error.
func (s *CheckoutService) resolveExpiry(in CreateCheckoutSessionInput) (time.Time, error) {
	now := s.clock.Now()
	exp := in.ExpiresAt
	if exp.IsZero() {
		if in.ExpiresInSeconds <= 0 {
			return time.Time{}, shared.NewValidationError("expires", "expires_at or a positive expires_in_seconds is required")
		}
		exp = now.Add(time.Duration(in.ExpiresInSeconds) * time.Second)
	}
	if !exp.After(now) {
		return time.Time{}, shared.NewValidationError("expires_at", "expiry must be in the future")
	}
	return exp, nil
}

// reservePayment returns the payment to bill for this session: an existing one for
// the idempotency key (returned to be resumed), or a freshly persisted pending
// payment reserving the key. On a uniqueness race the winner is returned (no double
// bill). Mirrors PixService.reservePayment for the checkout endpoint.
func (s *CheckoutService) reservePayment(ctx context.Context, tenantID, idemKey string, amount shared.Money) (*payment.Payment, error) {
	existing, err := s.payments.FindPaymentByIdempotencyKey(ctx, tenantID, idemKey)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("idempotency lookup: %w", err)
	}

	p, err := payment.New(s.ids.NewID(), tenantID, CheckoutCreateEndpoint, idemKey, amount, s.clock.Now())
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

// publishPaymentEvent best-effort publishes a payment lifecycle event. A publish
// failure must never fail the persisted session.
func (s *CheckoutService) publishPaymentEvent(ctx context.Context, topic string, p *payment.Payment) {
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

// buildCheckoutItems validates and converts the boundary items into domain Items.
// An empty or oversized list is a validation error (the domain also rejects empty,
// but failing fast here avoids reserving a payment for an obviously invalid request).
func buildCheckoutItems(in []CheckoutItemInput) ([]checkout.Item, error) {
	if len(in) == 0 {
		return nil, shared.NewValidationError("items", "at least one item is required")
	}
	if len(in) > maxCheckoutItems {
		return nil, shared.NewValidationError("items", "too many items")
	}
	out := make([]checkout.Item, 0, len(in))
	for _, it := range in {
		item, err := checkout.NewItem(strings.TrimSpace(it.Description), it.AmountCents)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// toCheckoutRequest maps a validated domain session to the PSP port request.
func toCheckoutRequest(sess checkout.Session, idemKey string) ports.CheckoutRequest {
	domainItems := sess.Items()
	items := make([]ports.CheckoutItem, len(domainItems))
	for i, it := range domainItems {
		items[i] = ports.CheckoutItem{Description: it.Description(), AmountCents: it.AmountCents()}
	}
	return ports.CheckoutRequest{
		TenantID:              sess.TenantID(),
		SessionID:             sess.ID(),
		Currency:              sess.Currency(),
		Items:                 items,
		ExpiresAt:             sess.ExpiresAt(),
		CardType:              string(sess.CardType()),
		RequireAuthentication: sess.RequireAuthentication(),
		MaxInstallments:       sess.MaxInstallments(),
		IdempotencyKey:        idemKey,
	}
}
