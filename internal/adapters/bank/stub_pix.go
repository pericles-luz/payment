package bank

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file extends StubProvider to back ports.PixProvider (PIX cobrança imediata,
// homologação roteiro 7.1–7.4) in-memory, so the use-cases and HTTP routes run
// end-to-end in stub mode (PAYMENT_C6_BASE_URL unset) without C6. The behaviour
// mirrors the real C6 adapter's observable contract: idempotent create keyed by the
// request's idempotency anchor, a deterministic BACEN-shaped txid, an ATIVA charge
// with QR material and an expiry, and reconcile/list reads. Like the other stub
// methods every call resolves the tenant credential first to demonstrate per-tenant
// isolation; the secret is never logged.

// compile-time assertion that StubProvider satisfies the PIX port.
var _ ports.PixProvider = (*StubProvider)(nil)

// stubDefaultPixExpiry is the immediate-charge QR lifetime applied when the caller
// passes a non-positive expiresIn (mirrors the C6 adapter default).
const stubDefaultPixExpiry = time.Hour

// stubPixTxID derives a deterministic, BACEN-shaped (32 hex chars, inside the
// 26..35 [a-zA-Z0-9] range) txid from the idempotency anchor, so a re-submit with
// the same anchor addresses the same charge — the stub's model of PSP idempotency.
func stubPixTxID(anchor string) string {
	sum := sha256.Sum256([]byte(anchor))
	return hex.EncodeToString(sum[:])[:32]
}

// pixAnchor returns the request's idempotency anchor: the IdempotencyKey when
// present, else the PaymentID.
func pixAnchor(req ports.ChargeRequest) string {
	if req.IdempotencyKey != "" {
		return req.IdempotencyKey
	}
	return req.PaymentID
}

// CreateImmediateCharge creates an ATIVA immediate PIX charge in-memory and returns
// its QR code and expiry. It is idempotent on the request's anchor: a re-submit with
// the same (tenant, anchor) returns the original charge without creating a new one.
// A non-positive amount or an empty anchor is rejected (complete mediation at the
// money seam, mirroring the C6 adapter).
func (s *StubProvider) CreateImmediateCharge(ctx context.Context, tenantID string, req ports.ChargeRequest, expiresIn time.Duration) (ports.PixChargeResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.PixChargeResult{}, err
	}
	anchor := pixAnchor(req)
	if anchor == "" || req.AmountCents <= 0 {
		return ports.PixChargeResult{}, shared.ErrValidation
	}
	if expiresIn <= 0 {
		expiresIn = stubDefaultPixExpiry
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if txID, ok := s.pixByIdem[key(tenantID, anchor)]; ok {
		return s.pixCharges[key(tenantID, txID)].result, nil // idempotent re-submit
	}

	now := s.now()
	txID := stubPixTxID(anchor)
	res := ports.PixChargeResult{
		TxID:                txID,
		Status:              "ATIVA",
		QRCodePayload:       "00020126-stub-" + txID,
		QRCodeLocation:      "https://pix.stub.example/qr/" + txID,
		ExpiresAt:           now.Add(expiresIn),
		ExpectedAmountCents: req.AmountCents,
	}
	s.pixCharges[key(tenantID, txID)] = stubPixCharge{result: res, createdAt: now}
	s.pixByIdem[key(tenantID, anchor)] = txID
	return res, nil
}

// GetImmediateCharge returns the authoritative state of an immediate PIX charge for
// reconciliation. An unknown txid (within the tenant) is shared.ErrNotFound.
func (s *StubProvider) GetImmediateCharge(ctx context.Context, tenantID, txID string) (ports.PixChargeResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.PixChargeResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.pixCharges[key(tenantID, txID)]
	if !ok {
		return ports.PixChargeResult{}, shared.ErrNotFound
	}
	return c.result, nil
}

// ListImmediateCharges returns the tenant's immediate PIX charges created within
// [Start,End] (inclusive), paginated. Results are ordered by creation instant so
// pagination is stable. PageSize <= 0 returns every match on page 0.
func (s *StubProvider) ListImmediateCharges(ctx context.Context, tenantID string, filter ports.PixListFilter) (ports.PixChargeList, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.PixChargeList{}, err
	}
	if filter.Start.IsZero() || filter.End.IsZero() {
		return ports.PixChargeList{}, shared.ErrValidation
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := tenantID + "\x00"
	matches := make([]stubPixCharge, 0)
	for k, c := range s.pixCharges {
		if len(k) < len(prefix) || k[:len(prefix)] != prefix {
			continue
		}
		if c.createdAt.Before(filter.Start) || c.createdAt.After(filter.End) {
			continue
		}
		matches = append(matches, c)
	}
	// Stable ascending order by creation instant (ties broken by txid) so paging is
	// deterministic across calls.
	sortStubPixCharges(matches)

	total := len(matches)
	pageSize := filter.PageSize
	page := filter.Page
	if pageSize <= 0 {
		pageSize = total
		page = 0
	}
	out := pageStubPixCharges(matches, page, pageSize)

	charges := make([]ports.PixChargeResult, 0, len(out))
	for _, c := range out {
		charges = append(charges, c.result)
	}
	totalPages := 0
	if pageSize > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	return ports.PixChargeList{
		Charges:    charges,
		Page:       page,
		PageSize:   pageSize,
		TotalItems: total,
		TotalPages: totalPages,
	}, nil
}

// sortStubPixCharges sorts in place by createdAt ascending, breaking ties by txid
// so the order is total and deterministic.
func sortStubPixCharges(cs []stubPixCharge) {
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && lessStubPixCharge(cs[j], cs[j-1]); j-- {
			cs[j], cs[j-1] = cs[j-1], cs[j]
		}
	}
}

func lessStubPixCharge(a, b stubPixCharge) bool {
	if a.createdAt.Equal(b.createdAt) {
		return a.result.TxID < b.result.TxID
	}
	return a.createdAt.Before(b.createdAt)
}

// pageStubPixCharges returns the page-th slice of size pageSize (0-based), or an
// empty slice when the page is out of range.
func pageStubPixCharges(cs []stubPixCharge, page, pageSize int) []stubPixCharge {
	if pageSize <= 0 {
		return nil
	}
	start := page * pageSize
	if start >= len(cs) {
		return nil
	}
	end := start + pageSize
	if end > len(cs) {
		end = len(cs)
	}
	return cs[start:end]
}
