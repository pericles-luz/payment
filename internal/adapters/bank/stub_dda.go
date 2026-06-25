package bank

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file extends StubProvider to back ports.DDAProvider (DDA / agendamento de
// pagamentos, roteiro grupo 8) in-memory, so the use-cases and HTTP routes run
// end-to-end in stub mode (PAYMENT_C6_BASE_URL unset) without C6. The behaviour
// mirrors the real C6 adapter's observable contract: per-tenant credential isolation
// resolved on every call (the secret is never logged), an idempotent consult create
// keyed by the idempotency anchor, deterministic group/item ids, and tenant-scoped
// reads/mutations where another tenant's group is shared.ErrNotFound (no cross-tenant
// existence oracle).

// compile-time assertion that StubProvider satisfies the DDA port.
var _ ports.DDAProvider = (*StubProvider)(nil)

// stubDDAGroup is the in-memory record of a DDA payment group: its status verbatim
// and the items currently in it.
type stubDDAGroup struct {
	status string
	items  []ports.DDAItem
}

// SeedDDABoletos sets the boletos open in a tenant's DDA (roteiro 8.1) for tests and
// local dev. It overwrites any previously seeded list for the tenant.
func (s *StubProvider) SeedDDABoletos(tenantID string, boletos []ports.DDABoleto) {
	s.mu.Lock()
	defer s.mu.Unlock()
	owned := make([]ports.DDABoleto, len(boletos))
	copy(owned, boletos)
	s.ddaBoletos[tenantID] = owned
}

// stubHash returns the first n hex chars of sha256(parts joined). It derives
// deterministic, opaque, non-sequential ids (group/item) from stable inputs.
func stubHash(n int, parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:n]
}

// stubBarcodeAmount derives a deterministic positive amount (cents) from a barcode's
// digits so a synthesised item is always valid (> 0) without external seeding.
func stubBarcodeAmount(barcode string) int64 {
	var sum int64
	for i := 0; i < len(barcode); i++ {
		sum += int64(barcode[i] - '0')
	}
	return (sum + 1) * 100 // at least 100 cents, deterministic
}

// ddaAnchor returns the request's idempotency anchor (the IdempotencyKey).
func ddaAnchor(req ports.DDAGroupRequest) string { return req.IdempotencyKey }

// ListOpenBoletos returns the boletos open in the tenant's DDA (roteiro 8.1). It
// resolves the tenant credential first (isolation) and returns a copy so a caller
// cannot mutate the stub's state.
func (s *StubProvider) ListOpenBoletos(ctx context.Context, tenantID string) ([]ports.DDABoleto, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.ddaBoletos[tenantID]
	out := make([]ports.DDABoleto, len(src))
	copy(out, src)
	return out, nil
}

// CreatePaymentGroup submits a consultando group from the requested barcodes (roteiro
// 8.2). It is idempotent on the request's anchor: a re-submit with the same (tenant,
// anchor) returns the original group. Each barcode is resolved into a deterministic
// item; an empty anchor or empty barcode list is rejected (complete mediation,
// mirroring the C6 adapter).
func (s *StubProvider) CreatePaymentGroup(ctx context.Context, tenantID string, req ports.DDAGroupRequest) (ports.DDAGroup, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.DDAGroup{}, err
	}
	anchor := ddaAnchor(req)
	if anchor == "" || len(req.Barcodes) == 0 {
		return ports.DDAGroup{}, shared.ErrValidation
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if groupID, ok := s.ddaGroupByIdem[key(tenantID, anchor)]; ok {
		return s.toDDAGroup(tenantID, groupID), nil // idempotent re-submit
	}

	groupID := "ddag_" + stubHash(24, tenantID, anchor)
	due := s.now().AddDate(0, 0, 7)
	items := make([]ports.DDAItem, len(req.Barcodes))
	for i, bc := range req.Barcodes {
		items[i] = ports.DDAItem{
			ID:          "ddai_" + stubHash(20, anchor, bc),
			Barcode:     bc,
			AmountCents: stubBarcodeAmount(bc),
			DueDate:     due,
		}
	}
	s.ddaGroups[key(tenantID, groupID)] = &stubDDAGroup{status: "consultando", items: items}
	s.ddaGroupByIdem[key(tenantID, anchor)] = groupID
	return s.toDDAGroup(tenantID, groupID), nil
}

// GetPaymentGroup returns the authoritative state of a group (roteiro 8.3 / the read
// the use-case runs before 8.4–8.6). An unknown group within the tenant is
// shared.ErrNotFound; the read is tenant-scoped so one tenant can never observe
// another's group.
func (s *StubProvider) GetPaymentGroup(ctx context.Context, tenantID, groupID string) (ports.DDAGroup, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return ports.DDAGroup{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ddaGroups[key(tenantID, groupID)]; !ok {
		return ports.DDAGroup{}, shared.ErrNotFound
	}
	return s.toDDAGroup(tenantID, groupID), nil
}

// RemovePaymentGroupItems removes a list of items from a group (roteiro 8.4). An
// unknown group is shared.ErrNotFound; removing an item id not present is a no-op (the
// transition legality is enforced by the domain in the use-case before this call).
func (s *StubProvider) RemovePaymentGroupItems(ctx context.Context, tenantID, groupID string, itemIDs []string) error {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.ddaGroups[key(tenantID, groupID)]
	if !ok {
		return shared.ErrNotFound
	}
	drop := make(map[string]bool, len(itemIDs))
	for _, id := range itemIDs {
		drop[id] = true
	}
	kept := g.items[:0:0]
	for _, it := range g.items {
		if !drop[it.ID] {
			kept = append(kept, it)
		}
	}
	g.items = kept
	return nil
}

// RemovePaymentGroupItem removes a single item from a group (roteiro 8.5). It reuses
// the list removal with a one-element list.
func (s *StubProvider) RemovePaymentGroupItem(ctx context.Context, tenantID, groupID, itemID string) error {
	return s.RemovePaymentGroupItems(ctx, tenantID, groupID, []string{itemID})
}

// SubmitPaymentGroup submits a group for approval (roteiro 8.6), flipping its status
// to aprovado. It is idempotent: submitting an already-approved group succeeds. An
// unknown group is shared.ErrNotFound. idemKey is accepted for parity with the real
// adapter (which forwards it as Idempotency-Key); resource-state idempotency makes
// re-submission safe regardless.
func (s *StubProvider) SubmitPaymentGroup(ctx context.Context, tenantID, groupID, idemKey string) error {
	if _, err := s.creds.GetBankCredential(ctx, tenantID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.ddaGroups[key(tenantID, groupID)]
	if !ok {
		return shared.ErrNotFound
	}
	g.status = "aprovado"
	return nil
}

// toDDAGroup snapshots a stored group into a transport DDAGroup with copied items. The
// caller holds s.mu.
func (s *StubProvider) toDDAGroup(tenantID, groupID string) ports.DDAGroup {
	g := s.ddaGroups[key(tenantID, groupID)]
	items := make([]ports.DDAItem, len(g.items))
	copy(items, g.items)
	return ports.DDAGroup{ID: groupID, Status: g.status, Items: items}
}
