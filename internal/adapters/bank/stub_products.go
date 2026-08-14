package bank

import (
	"context"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file extends StubProvider to back the C6-C product ports (BolePix
// boleto, unified checkout) in-memory, so wiring and use-cases run end-to-end
// without an external dependency. Like CreateCharge, every method resolves the
// tenant's credential first to demonstrate per-tenant isolation; the secret is
// never logged.

// compile-time assertions that StubProvider satisfies the C6-C product ports.
var (
	_ ports.BoletoProvider   = (*StubProvider)(nil)
	_ ports.CheckoutProvider = (*StubProvider)(nil)
)

// CreateBoleto registers a boleto deterministically, deriving a txid from the
// boleto id and returning placeholder scannable artifacts. The registered state
// (including the fine/interest/discount parameters) is retained so GetBoleto can
// reconcile it (roteiro 6.a). Registration is idempotent on (tenant, boleto id): a
// repeat call returns the existing record rather than registering a new boleto.
func (s *StubProvider) CreateBoleto(ctx context.Context, tenantID string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.BoletoResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, req.BoletoID)
	if prev, ok := s.boletos[k]; ok {
		return prev, nil // PSP dedupe: same (tenant, id) => same boleto, no new effect
	}
	res := ports.BoletoResult{
		BoletoID:           req.BoletoID,
		TxID:               "tx_" + req.BoletoID,
		Status:             "REGISTERED",
		QRCode:             "pix-emv-" + req.BoletoID,
		Barcode:            "barcode-" + req.BoletoID,
		AmountCents:        req.AmountCents,
		DueDate:            req.DueDate,
		ValidUntil:         req.ValidUntil,
		FineBps:            req.FineBps,
		FineFixedCents:     req.FineFixedCents,
		MonthlyInterestBps: req.MonthlyInterestBps,
		Discounts:          req.Discounts,
	}
	s.boletos[k] = res
	return res, nil
}

// GetBoleto returns the authoritative state of a registered boleto for the tenant
// (roteiro 6.a). An unknown id within the tenant is shared.ErrNotFound; the read is
// keyed by (tenant, id) so one tenant can never observe another's boleto.
func (s *StubProvider) GetBoleto(ctx context.Context, tenantID, boletoID string) (ports.BoletoResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.BoletoResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.boletos[key(tenantID, boletoID)]
	if !ok {
		return ports.BoletoResult{}, shared.ErrNotFound
	}
	return res, nil
}

// CancelBoleto performs the baixa/cancelamento of a registered boleto (roteiro grupo
// 4). It is idempotent: a second cancel of an already-cancelled boleto succeeds and
// returns the cancelled state. An unknown (tenant, id) is shared.ErrNotFound, so one
// tenant can never cancel another's boleto.
func (s *StubProvider) CancelBoleto(ctx context.Context, tenantID, boletoID string) (ports.BoletoResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.BoletoResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, boletoID)
	res, ok := s.boletos[k]
	if !ok {
		return ports.BoletoResult{}, shared.ErrNotFound
	}
	res.Status = "CANCELLED"
	s.boletos[k] = res
	return res, nil
}

// UpdateBoleto amends a registered boleto's mutable parameters (roteiro grupo 5),
// preserving its identity and scannable artifacts. An unknown (tenant, id) is
// shared.ErrNotFound, so one tenant can never amend another's boleto.
func (s *StubProvider) UpdateBoleto(ctx context.Context, tenantID, boletoID string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.BoletoResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, boletoID)
	res, ok := s.boletos[k]
	if !ok {
		return ports.BoletoResult{}, shared.ErrNotFound
	}
	// Amend only the mutable parameters; identity (id/txid) and artifacts stay put.
	res.AmountCents = req.AmountCents
	res.DueDate = req.DueDate
	res.ValidUntil = req.ValidUntil
	res.FineBps = req.FineBps
	res.FineFixedCents = req.FineFixedCents
	res.MonthlyInterestBps = req.MonthlyInterestBps
	res.Discounts = req.Discounts
	s.boletos[k] = res
	return res, nil
}

// CreateCheckoutSession opens a checkout session deterministically, summing the
// item amounts and returning a placeholder hosted redirect URL. The session is
// retained (keyed by tenant+id) so GetCheckoutSession can reconcile it (roteiro 10)
// and CancelCheckoutSession can cancel it (roteiro 11). Opening is idempotent on
// (tenant, session id): a repeat call returns the existing record rather than
// re-opening, modelling the PSP collapsing a retried open.
func (s *StubProvider) CreateCheckoutSession(ctx context.Context, tenantID string, req ports.CheckoutRequest) (ports.CheckoutResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.CheckoutResult{}, err
	}
	var sum int64
	for _, it := range req.Items {
		sum += it.AmountCents
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, req.SessionID)
	if prev, ok := s.checkouts[k]; ok {
		return prev, nil // PSP dedupe: same (tenant, id) => same session, no new effect
	}
	res := ports.CheckoutResult{
		SessionID:             req.SessionID,
		Status:                "OPEN",
		RedirectURL:           "https://checkout.c6.example/" + req.SessionID,
		AmountCents:           sum,
		CardType:              req.CardType,
		RequireAuthentication: req.RequireAuthentication,
	}
	s.checkouts[k] = res
	return res, nil
}

// GetCheckoutSession returns the authoritative state of a checkout session for the
// tenant (roteiro 10). An unknown id within the tenant is shared.ErrNotFound; the read
// is keyed by (tenant, id) so one tenant can never observe another's session.
func (s *StubProvider) GetCheckoutSession(ctx context.Context, tenantID, sessionID string) (ports.CheckoutResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.CheckoutResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.checkouts[key(tenantID, sessionID)]
	if !ok {
		return ports.CheckoutResult{}, shared.ErrNotFound
	}
	return res, nil
}

// CancelCheckoutSession cancels a checkout session (roteiro 11). It is idempotent: a
// second cancel of an already-cancelled session succeeds and returns the cancelled
// state. The redirect URL is cleared on cancel (a cancelled session is not payable).
// An unknown (tenant, id) is shared.ErrNotFound, so one tenant can never cancel
// another's session.
func (s *StubProvider) CancelCheckoutSession(ctx context.Context, tenantID, sessionID string) (ports.CheckoutResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.CheckoutResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, sessionID)
	res, ok := s.checkouts[k]
	if !ok {
		return ports.CheckoutResult{}, shared.ErrNotFound
	}
	res.Status = "CANCELLED"
	res.RedirectURL = ""
	s.checkouts[k] = res
	return res, nil
}

// MarkCheckoutPaid flips a checkout session to paid and reconciles the full authorized
// total (test/dev hook simulating the PSP capturing a correctly-paid session): the
// received amount equals the expected total so AmountReconciled holds. A no-op for an
// unknown session.
func (s *StubProvider) MarkCheckoutPaid(tenantID, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, sessionID)
	if res, ok := s.checkouts[k]; ok {
		res.Status = "paid"
		res.ReceivedAmountCents = res.AmountCents
		s.checkouts[k] = res
	}
}

// MarkCheckoutPaidWithReceived flips a checkout session to paid with a specific
// received amount (test/dev hook simulating a divergent capture: partial payment or
// overpayment). When received != expected, AmountReconciled is false and settlement
// must be refused. A no-op for an unknown session.
func (s *StubProvider) MarkCheckoutPaidWithReceived(tenantID, sessionID string, receivedCents int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, sessionID)
	if res, ok := s.checkouts[k]; ok {
		res.Status = "paid"
		res.ReceivedAmountCents = receivedCents
		s.checkouts[k] = res
	}
}
