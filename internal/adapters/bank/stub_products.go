package bank

import (
	"context"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file extends StubProvider to back the C6-C product ports (PIX Automático
// consent, BolePix boleto, unified checkout) in-memory, so wiring and use-cases
// run end-to-end without an external dependency. Like CreateCharge, every method
// resolves the tenant's credential first to demonstrate per-tenant isolation; the
// secret is never logged.

// compile-time assertions that StubProvider satisfies the C6-C product ports.
var (
	_ ports.ConsentProvider  = (*StubProvider)(nil)
	_ ports.BoletoProvider   = (*StubProvider)(nil)
	_ ports.CheckoutProvider = (*StubProvider)(nil)
)

// CreateConsent registers a recurring-debit consent deterministically. A repeat
// call for the same (tenant, consent id) returns the existing consent rather than
// creating a new one, modelling PSP-side idempotency.
func (s *StubProvider) CreateConsent(ctx context.Context, tenantID string, req ports.ConsentRequest) (ports.ConsentResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.ConsentResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, req.ConsentID)
	if prev, ok := s.consents[k]; ok {
		return prev, nil
	}
	res := ports.ConsentResult{ConsentID: req.ConsentID, Status: "PENDING"}
	s.consents[k] = res
	return res, nil
}

// GetConsent returns the authoritative state of a consent for reconciliation.
func (s *StubProvider) GetConsent(ctx context.Context, tenantID, consentID string) (ports.ConsentResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.ConsentResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.consents[key(tenantID, consentID)]
	if !ok {
		return ports.ConsentResult{}, shared.ErrNotFound
	}
	return res, nil
}

// CancelConsent revokes a consent. Cancelling is idempotent: a second cancel of an
// already-cancelled consent succeeds and returns the cancelled state.
func (s *StubProvider) CancelConsent(ctx context.Context, tenantID, consentID string) (ports.ConsentResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.ConsentResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, consentID)
	res, ok := s.consents[k]
	if !ok {
		return ports.ConsentResult{}, shared.ErrNotFound
	}
	res.Status = "CANCELLED"
	s.consents[k] = res
	return res, nil
}

// CreateBoleto registers a boleto deterministically, deriving a txid from the
// boleto id and returning placeholder scannable artifacts.
func (s *StubProvider) CreateBoleto(ctx context.Context, tenantID string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.BoletoResult{}, err
	}
	return ports.BoletoResult{
		BoletoID:    req.BoletoID,
		TxID:        "tx_" + req.BoletoID,
		Status:      "REGISTERED",
		QRCode:      "pix-emv-" + req.BoletoID,
		Barcode:     "barcode-" + req.BoletoID,
		AmountCents: req.AmountCents,
	}, nil
}

// CreateCheckoutSession opens a checkout session deterministically, summing the
// item amounts and returning a placeholder hosted redirect URL.
func (s *StubProvider) CreateCheckoutSession(ctx context.Context, tenantID string, req ports.CheckoutRequest) (ports.CheckoutResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.CheckoutResult{}, err
	}
	var sum int64
	for _, it := range req.Items {
		sum += it.AmountCents
	}
	return ports.CheckoutResult{
		SessionID:   req.SessionID,
		Status:      "OPEN",
		RedirectURL: "https://checkout.c6.example/" + req.SessionID,
		AmountCents: sum,
	}, nil
}
