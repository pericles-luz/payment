package bank

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file extends StubProvider to back ports.PixDueChargeProvider (PIX cobrança
// com vencimento, cobv — roteiro 7.5–7.7) in-memory, so the use-cases and HTTP
// routes run end-to-end in stub mode (PAYMENT_C6_BASE_URL unset) without C6. The
// behaviour mirrors the real C6 adapter's observable contract: idempotent create
// keyed by the idempotency anchor, a deterministic BACEN-shaped txid, an ATIVA
// charge with QR material, and reconcile/amend reads. Every call resolves the
// tenant credential first to demonstrate per-tenant isolation; the secret is never
// logged.
//
// A created cobv charge is ALSO recorded in the generic charges map (the bank's
// charge-read surface) so the unsigned C6 webhook (C6-D) can reconcile-before-settle
// it through ports.BankProvider.GetCharge: a cobv settlement notification is then
// exercised end-to-end in Camada A without a second webhook endpoint (roteiro 7.8).
// A test drives the paid transition via MarkSettled(tenant, txid).

// compile-time assertion that StubProvider satisfies the cobv port.
var _ ports.PixDueChargeProvider = (*StubProvider)(nil)

// stubCobvTxID derives a deterministic, BACEN-shaped (32 hex chars, inside the
// 26..35 [a-zA-Z0-9] range) txid from the idempotency anchor.
func stubCobvTxID(anchor string) string {
	sum := sha256.Sum256([]byte(anchor))
	return hex.EncodeToString(sum[:])[:32]
}

// cobvAnchor returns the request's idempotency anchor: the IdempotencyKey when
// present, else the TxID.
func cobvAnchor(req ports.PixDueChargeRequest) string {
	if req.IdempotencyKey != "" {
		return req.IdempotencyKey
	}
	return req.TxID
}

// CreateDueCharge registers an ATIVA cobv charge in-memory and returns its QR code.
// It is idempotent on the request's anchor: a re-submit with the same (tenant,
// anchor) returns the original charge without creating a new one. A non-positive
// amount or an empty anchor is rejected (complete mediation at the money seam,
// mirroring the C6 adapter).
func (s *StubProvider) CreateDueCharge(ctx context.Context, tenantID string, req ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.PixDueChargeResult{}, err
	}
	anchor := cobvAnchor(req)
	if anchor == "" || req.AmountCents <= 0 {
		return ports.PixDueChargeResult{}, shared.ErrValidation
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if txID, ok := s.cobvDueByIdem[key(tenantID, anchor)]; ok {
		return s.cobvCharges[key(tenantID, txID)], nil // idempotent re-submit
	}

	txID := stubCobvTxID(anchor)
	res := ports.PixDueChargeResult{
		TxID:                txID,
		Status:              "ATIVA",
		QRCodePayload:       "00020126-cobv-" + txID,
		QRCodeLocation:      "https://pix.stub.example/cobv/" + txID,
		DueDate:             req.DueDate,
		ValidityDays:        req.ValidityDays,
		FineBps:             req.FineBps,
		MonthlyInterestBps:  req.MonthlyInterestBps,
		DiscountBps:         req.DiscountBps,
		DiscountFixedCents:  req.DiscountFixedCents,
		ExpectedAmountCents: req.AmountCents,
	}
	s.cobvCharges[key(tenantID, txID)] = res
	s.cobvDueByIdem[key(tenantID, anchor)] = txID
	// Make the charge reconcilable via the bank's generic charge-read so the C6
	// webhook can reconcile-before-settle it (roteiro 7.8). Status starts ATIVA
	// (unpaid); MarkSettled flips it to paid with the full received amount.
	s.charges[key(tenantID, txID)] = ports.ChargeResult{
		TxID:                txID,
		Status:              "ATIVA",
		ExpectedAmountCents: req.AmountCents,
	}
	return res, nil
}

// GetDueCharge returns the authoritative state of a cobv charge for reconciliation.
// An unknown txid (within the tenant) is shared.ErrNotFound.
func (s *StubProvider) GetDueCharge(ctx context.Context, tenantID, txID string) (ports.PixDueChargeResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.PixDueChargeResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.cobvCharges[key(tenantID, txID)]
	if !ok {
		return ports.PixDueChargeResult{}, shared.ErrNotFound
	}
	return res, nil
}

// UpdateDueCharge amends a registered cobv's parameters, preserving its identity
// (txid). An unknown txid (within the tenant) is shared.ErrNotFound; the operation
// is tenant-scoped so one tenant can never amend another's charge.
func (s *StubProvider) UpdateDueCharge(ctx context.Context, tenantID, txID string, req ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.PixDueChargeResult{}, err
	}
	if req.AmountCents <= 0 {
		return ports.PixDueChargeResult{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.cobvCharges[key(tenantID, txID)]
	if !ok {
		return ports.PixDueChargeResult{}, shared.ErrNotFound
	}
	existing.DueDate = req.DueDate
	existing.ValidityDays = req.ValidityDays
	existing.FineBps = req.FineBps
	existing.MonthlyInterestBps = req.MonthlyInterestBps
	existing.DiscountBps = req.DiscountBps
	existing.DiscountFixedCents = req.DiscountFixedCents
	existing.ExpectedAmountCents = req.AmountCents
	s.cobvCharges[key(tenantID, txID)] = existing
	// Keep the reconcile surface consistent with the amended expected amount.
	if c, ok := s.charges[key(tenantID, txID)]; ok {
		c.ExpectedAmountCents = req.AmountCents
		s.charges[key(tenantID, txID)] = c
	}
	return existing, nil
}
