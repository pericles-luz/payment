package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/boleto"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// BoletoCreateEndpoint is the billable endpoint key for registering a BolePix
// boleto. It anchors per-tenant pricing exactly like pix.create/checkout.create; a
// tenant without a configured price for it cannot register a boleto.
const BoletoCreateEndpoint = "boleto.create"

// maxBoletoDiscountTiers bounds the discount schedule so a single request cannot push
// an unbounded list to the PSP (defense-in-depth with the HTTP body cap).
const maxBoletoDiscountTiers = 12

// BoletoService registers BolePix boletos and reads them back (roteiro grupos 1–3 +
// 6). Register mirrors PixService/CheckoutService financial-integrity ordering: the
// idempotency key is reserved (pending payment for the principal persisted, unique
// index serialising racers) BEFORE the PSP is called, then the bank tx id and the
// ledger (billing) entry are persisted atomically. Get is a pure reconcile read. The
// tenant is always the authenticated tenant, never client input.
type BoletoService struct {
	payments ports.PaymentRepository
	tenants  ports.TenantRepository
	pricing  ports.PricingRepository
	boleto   ports.BoletoProvider
	bus      ports.MessageBus
	clock    ports.Clock
	ids      ports.IDProvider
	uow      ports.UnitOfWork
}

// NewBoletoService wires a BoletoService from the provided ports.
func NewBoletoService(d Deps) *BoletoService {
	return &BoletoService{
		payments: d.Payments,
		tenants:  d.Tenants,
		pricing:  d.Pricing,
		boleto:   d.Boleto,
		bus:      d.Bus,
		clock:    d.Clock,
		ids:      d.IDs,
		uow:      resolveUoW(d),
	}
}

// DiscountTierInput is one validated early-payment discount step at the boundary
// (roteiro grupo 3). Exactly one of Bps/FixedCents must be set.
type DiscountTierInput struct {
	DaysBeforeDue int
	Bps           int64
	FixedCents    int64
}

// BoletoAddressInput is the payer's address at the boundary (ADR-0005). Number is an
// integer to mirror the C6 contract; "S/N"/alphanumeric numbers are an open
// homologation question handled at the adapter/contract level.
type BoletoAddressInput struct {
	Street  string
	Number  int
	City    string
	State   string
	ZipCode string
}

// BoletoPayerInput is the boleto sacado/pagador at the boundary. It is optional at the
// app layer (kept lenient like the stub); the real C6 contract's mandatory-payer rule
// is enforced in the C6 adapter, not here, so the stub and its tests stay green
// (ADR-0005). When fields are present they are structurally validated.
type BoletoPayerInput struct {
	Name    string
	TaxID   string
	Address BoletoAddressInput
}

// RegisterBoletoInput is the validated boundary input for registering a boleto.
// TenantID is the authenticated tenant. DueDate is the vencimento; FineBps and
// MonthlyInterestBps are the late-payment rates (groups 1–2); Discounts is the
// optional early-payment schedule (group 3). Payer is the sacado/pagador (ADR-0005).
type RegisterBoletoInput struct {
	TenantID string
	// AccountID is the owning account resolved at the auth choke-point (SIN-69126),
	// stamped on the ledger for account→tenant→endpoint metering (SIN-69127).
	// Attribution-only; empty = self-account. See CreateChargeInput.AccountID.
	AccountID   string
	AmountCents int64
	Currency    string
	DueDate     time.Time
	FineBps     int64
	// FineFixedCents expresses the late-payment fine as a fixed amount instead of a
	// percentage (roteiro 2.c). Mutually exclusive with FineBps.
	FineFixedCents     int64
	MonthlyInterestBps int64
	Discounts          []DiscountTierInput
	Payer              BoletoPayerInput
	IdempotencyKey     string
}

// RegisterBoleto registers a boleto at the bank and records the billable event,
// returning the persisted payment (reserving the principal) together with the bank's
// scannable artifacts and registered parameters. The payment id doubles as the stable
// boleto id, so retrying with the same idempotency key rebuilds the same id and the
// PSP collapses the retry without billing again.
func (s *BoletoService) RegisterBoleto(ctx context.Context, in RegisterBoletoInput) (*payment.Payment, ports.BoletoResult, error) {
	t, err := s.tenants.FindTenantByID(ctx, in.TenantID)
	if err != nil {
		return nil, ports.BoletoResult{}, fmt.Errorf("resolve tenant: %w", err)
	}
	if !t.Active() {
		return nil, ports.BoletoResult{}, shared.NewValidationError("tenant", "tenant is not active")
	}
	if in.IdempotencyKey == "" {
		return nil, ports.BoletoResult{}, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	if err := validateBoletoPayer(in.Payer); err != nil {
		return nil, ports.BoletoResult{}, err
	}

	principal, err := shared.NewMoney(in.AmountCents, in.Currency)
	if err != nil {
		return nil, ports.BoletoResult{}, err
	}
	tiers, err := buildDiscountTiers(in.Discounts)
	if err != nil {
		return nil, ports.BoletoResult{}, err
	}
	// Validate the whole boleto in the core BEFORE reserving a payment, so an invalid
	// request (bad due date, fine/interest over cap, malformed discount schedule)
	// never leaves a reserved-but-unusable payment behind. The id here is a throwaway;
	// the canonical boleto is rebuilt with the payment id below.
	if _, err := newDomainBoleto("validate", in, principal, tiers); err != nil {
		return nil, ports.BoletoResult{}, err
	}

	price, err := s.pricing.GetEndpointPrice(ctx, in.TenantID, BoletoCreateEndpoint)
	if err != nil {
		return nil, ports.BoletoResult{}, fmt.Errorf("resolve price: %w", err)
	}

	p, err := s.reservePayment(ctx, in.TenantID, in.IdempotencyKey, principal)
	if err != nil {
		return nil, ports.BoletoResult{}, err
	}

	b, err := newDomainBoleto(p.ID(), in, principal, tiers)
	if err != nil {
		return nil, ports.BoletoResult{}, err
	}

	res, err := s.boleto.CreateBoleto(ctx, in.TenantID, toBoletoRequest(b, in.Payer, in.IdempotencyKey))
	if err != nil {
		return nil, ports.BoletoResult{}, fmt.Errorf("bank create boleto: %w", err)
	}

	if p.TxID() != "" {
		// Already registered and billed by a prior request with this key: return the
		// (idempotent) PSP result without billing again.
		return p, res, nil
	}
	p.SetTxID(res.TxID)

	entry, err := billing.NewLedgerEntry(s.ids.NewID(), in.TenantID, BoletoCreateEndpoint, p.ID(), price.PriceCents(), s.clock.Now(), billing.WithAccount(in.AccountID))
	if err != nil {
		return nil, ports.BoletoResult{}, err
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
		return nil, ports.BoletoResult{}, err
	}

	if finalized {
		s.publishBoletoEvent(ctx, TopicPaymentCreated, p)
	}
	return p, res, nil
}

// GetBoleto reconciles the authoritative state of a boleto from the bank for the
// authenticated tenant (roteiro 6.a). An unknown id surfaces as not-found (no
// cross-tenant disclosure: the bank read is tenant-scoped).
func (s *BoletoService) GetBoleto(ctx context.Context, tenantID, boletoID string) (ports.BoletoResult, error) {
	boletoID = strings.TrimSpace(boletoID)
	if boletoID == "" {
		return ports.BoletoResult{}, shared.NewValidationError("id", "boleto id is required")
	}
	return s.boleto.GetBoleto(ctx, tenantID, boletoID)
}

// CancelBoleto performs the baixa/cancelamento of a registered boleto for the
// authenticated tenant (roteiro grupo 4 — a-vencer 4.a / vencido 4.b). It is a state
// change on an already-billed boleto, so it does not bill again. An unknown id
// surfaces as not-found (tenant-scoped: no cross-tenant cancel, no existence oracle).
func (s *BoletoService) CancelBoleto(ctx context.Context, tenantID, boletoID string) error {
	boletoID = strings.TrimSpace(boletoID)
	if boletoID == "" {
		return shared.NewValidationError("id", "boleto id is required")
	}
	_, err := s.boleto.CancelBoleto(ctx, tenantID, boletoID)
	return err
}

// UpdateBoletoInput is the validated boundary input for amending a boleto (roteiro
// grupo 5): due date (5.a), validity (5.b), amount/fine/interest (5.c). It mirrors
// the registration fields minus the payer (the payer is not amended here).
type UpdateBoletoInput struct {
	TenantID           string
	AmountCents        int64
	Currency           string
	DueDate            time.Time
	ValidUntil         time.Time
	FineBps            int64
	FineFixedCents     int64
	MonthlyInterestBps int64
	Discounts          []DiscountTierInput
	IdempotencyKey     string
}

// UpdateBoleto amends a registered boleto's parameters for the authenticated tenant
// (roteiro grupo 5). Like the register path, the full new parameter set is validated
// in the core before it reaches the bank; the amendment is idempotent on the
// forwarded key. It does not bill again (the boleto was billed at registration). An
// unknown id surfaces as not-found (tenant-scoped: no cross-tenant amend).
func (s *BoletoService) UpdateBoleto(ctx context.Context, tenantID, boletoID string, in UpdateBoletoInput) (ports.BoletoResult, error) {
	boletoID = strings.TrimSpace(boletoID)
	if boletoID == "" {
		return ports.BoletoResult{}, shared.NewValidationError("id", "boleto id is required")
	}
	if in.IdempotencyKey == "" {
		return ports.BoletoResult{}, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	principal, err := shared.NewMoney(in.AmountCents, in.Currency)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	tiers, err := buildDiscountTiers(in.Discounts)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	b, err := buildBoleto(boletoID, tenantID, principal, in.DueDate, in.ValidUntil, in.FineBps, in.FineFixedCents, in.MonthlyInterestBps, tiers)
	if err != nil {
		return ports.BoletoResult{}, err
	}
	return s.boleto.UpdateBoleto(ctx, tenantID, boletoID, toBoletoRequest(b, BoletoPayerInput{}, in.IdempotencyKey))
}

// reservePayment returns the payment to bill for this boleto: an existing one for the
// idempotency key (returned to be resumed), or a freshly persisted pending payment
// reserving the key. On a uniqueness race the winner is returned (no double bill).
// Mirrors CheckoutService.reservePayment for the boleto endpoint.
func (s *BoletoService) reservePayment(ctx context.Context, tenantID, idemKey string, amount shared.Money) (*payment.Payment, error) {
	existing, err := s.payments.FindPaymentByIdempotencyKey(ctx, tenantID, idemKey)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, fmt.Errorf("idempotency lookup: %w", err)
	}

	p, err := payment.New(s.ids.NewID(), tenantID, BoletoCreateEndpoint, idemKey, amount, s.clock.Now())
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

// publishBoletoEvent best-effort publishes a payment lifecycle event. A publish
// failure must never fail the persisted boleto.
func (s *BoletoService) publishBoletoEvent(ctx context.Context, topic string, p *payment.Payment) {
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

// newDomainBoleto builds and validates the canonical domain boleto for registration.
func newDomainBoleto(id string, in RegisterBoletoInput, principal shared.Money, tiers []boleto.DiscountTier) (boleto.Boleto, error) {
	return buildBoleto(id, in.TenantID, principal, in.DueDate, time.Time{}, in.FineBps, in.FineFixedCents, in.MonthlyInterestBps, tiers)
}

// buildBoleto constructs and validates a domain boleto from primitive parameters,
// attaching the fixed fine (roteiro 2.c), the validity limit (5.b) and the discount
// schedule (grupo 3) when present. All invariants are enforced in the core; this is
// the single validation path shared by register and amend.
func buildBoleto(id, tenantID string, principal shared.Money, dueDate, validUntil time.Time, fineBps, fineFixedCents, monthlyInterestBps int64, tiers []boleto.DiscountTier) (boleto.Boleto, error) {
	b, err := boleto.New(id, tenantID, principal, dueDate, fineBps, monthlyInterestBps)
	if err != nil {
		return boleto.Boleto{}, err
	}
	if fineFixedCents > 0 {
		b, err = b.WithFixedFine(fineFixedCents)
		if err != nil {
			return boleto.Boleto{}, err
		}
	}
	if !validUntil.IsZero() {
		b, err = b.WithValidUntil(validUntil)
		if err != nil {
			return boleto.Boleto{}, err
		}
	}
	return b.WithDiscounts(tiers...)
}

// buildDiscountTiers converts the boundary discount tiers into domain tiers. An
// oversized schedule is a validation error (the domain also validates ordering and
// value invariants; failing fast on size avoids reserving a payment for an obviously
// invalid request).
func buildDiscountTiers(in []DiscountTierInput) ([]boleto.DiscountTier, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > maxBoletoDiscountTiers {
		return nil, shared.NewValidationError("discounts", "too many discount tiers")
	}
	out := make([]boleto.DiscountTier, len(in))
	for i, d := range in {
		out[i] = boleto.DiscountTier{DaysBeforeDue: d.DaysBeforeDue, Bps: d.Bps, FixedCents: d.FixedCents}
	}
	return out, nil
}

// toBoletoRequest maps a validated domain boleto to the PSP port request. The boleto
// id is taken from the domain object (b.ID()); payer/idemKey are supplied by the
// caller (register carries a payer; amend passes the zero payer).
func toBoletoRequest(b boleto.Boleto, payer BoletoPayerInput, idemKey string) ports.BoletoRequest {
	domainTiers := b.Discounts()
	tiers := make([]ports.BoletoDiscountTier, len(domainTiers))
	for i, d := range domainTiers {
		tiers[i] = ports.BoletoDiscountTier{DaysBeforeDue: d.DaysBeforeDue, Bps: d.Bps, FixedCents: d.FixedCents}
	}
	return ports.BoletoRequest{
		TenantID:           b.TenantID(),
		BoletoID:           b.ID(),
		AmountCents:        b.Principal().Cents(),
		Currency:           b.Principal().Currency(),
		DueDate:            b.DueDate(),
		ValidUntil:         b.ValidUntil(),
		FineBps:            b.FineBps(),
		FineFixedCents:     b.FineFixedCents(),
		MonthlyInterestBps: b.MonthlyInterestBps(),
		Discounts:          tiers,
		Payer:              toPortBoletoPayer(payer),
		IdempotencyKey:     idemKey,
	}
}

// toPortBoletoPayer maps the boundary payer to the port value object, trimming the
// tax id (mirrors the prior PayerTaxID handling).
func toPortBoletoPayer(in BoletoPayerInput) ports.BoletoPayer {
	return ports.BoletoPayer{
		Name:  strings.TrimSpace(in.Name),
		TaxID: strings.TrimSpace(in.TaxID),
		Address: ports.BoletoAddress{
			Street:  strings.TrimSpace(in.Address.Street),
			Number:  in.Address.Number,
			City:    strings.TrimSpace(in.Address.City),
			State:   strings.TrimSpace(in.Address.State),
			ZipCode: strings.TrimSpace(in.Address.ZipCode),
		},
	}
}

// validateBoletoPayer enforces the optional payer at the boundary: the payer may be
// omitted entirely (the C6 adapter is the one that requires it — ADR-0005), but any
// field that IS present must be structurally valid. The tax id, when present, must be
// a syntactically valid CPF (11) or CNPJ (14); the UF, when present, must be 2 letters;
// the CEP, when present, must be 8 digits. Mirrors the PIX devedor guard.
func validateBoletoPayer(p BoletoPayerInput) error {
	if taxID := strings.TrimSpace(p.TaxID); taxID != "" && !validTaxID(taxID) {
		return shared.NewValidationError("payer.tax_id", "payer tax id must be 11 (CPF) or 14 (CNPJ) digits")
	}
	if uf := strings.TrimSpace(p.Address.State); uf != "" && !validUF(uf) {
		return shared.NewValidationError("payer.address.state", "payer address state must be a 2-letter UF")
	}
	if cep := strings.TrimSpace(p.Address.ZipCode); cep != "" && !validCEP(cep) {
		return shared.NewValidationError("payer.address.zip_code", "payer address zip code must be 8 digits")
	}
	return nil
}

// validUF reports whether s is two ASCII letters (a Brazilian state abbreviation).
func validUF(s string) bool {
	if len(s) != 2 {
		return false
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

// validCEP reports whether s is exactly 8 ASCII digits (a Brazilian postal code).
func validCEP(s string) bool {
	if len(s) != 8 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
