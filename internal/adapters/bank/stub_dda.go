package bank

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/dda"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file extends StubProvider to back ports.DDAProvider (Agendamento de
// Pagamentos, roteiro grupo AP) in-memory, so the use-cases and HTTP routes run
// end-to-end in stub mode (PAYMENT_C6_BASE_URL unset) without C6. The behaviour
// mirrors the real C6 adapter's observable contract: per-tenant credential isolation
// resolved on every call (the secret is never logged), an idempotent consult create
// keyed by the idempotency anchor, deterministic group/item ids, and tenant-scoped
// reads/mutations where another tenant's group is shared.ErrNotFound (no cross-tenant
// existence oracle).
//
// Two behaviours are copied from the real contract ON PURPOSE, because getting them
// wrong here is what let the old adapter drift:
//
//   - the create answers with the group id ALONE, no items — so a caller that skips
//     the read-back breaks in stub mode too, not only against the bank;
//   - there is no group status: submitting flips every ITEM to SCHEDULED, which is
//     what the real API reports and what dda.PaymentGroup.IsSubmitted reads.

// compile-time assertion that StubProvider satisfies the Agendamento port.
var _ ports.DDAProvider = (*StubProvider)(nil)

// stubDDAGroup is the in-memory record of a payment group: the items currently in it.
// There is no status field — see the file comment.
type stubDDAGroup struct {
	items []ports.DDAItem
}

// SeedDDABoletos sets the bonds open in a tenant's DDA (roteiro AP_02) for tests and
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

// ddaAnchor returns the request's idempotency anchor (the IdempotencyKey).
func ddaAnchor(req ports.DDAGroupRequest) string { return req.IdempotencyKey }

// ListOpenBoletos returns the bonds open in the tenant's DDA (roteiro AP_02). It
// resolves the tenant credential first (isolation) and returns a copy so a caller
// cannot mutate the stub's state.
func (s *StubProvider) ListOpenBoletos(ctx context.Context, tenantID string) ([]ports.DDABoleto, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.ddaBoletos[tenantID]
	out := make([]ports.DDABoleto, len(src))
	copy(out, src)
	return out, nil
}

// CreatePaymentGroup registers a group from the requested payments (roteiro AP_01)
// and answers with its id alone. It is idempotent on the request's anchor: a
// re-submit with the same (tenant, anchor) returns the original group id. An empty
// anchor, an empty payment list, or a payment without a reference or a positive
// amount is rejected (complete mediation, mirroring the C6 adapter).
func (s *StubProvider) CreatePaymentGroup(ctx context.Context, tenantID string, req ports.DDAGroupRequest) (ports.DDAGroup, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.DDAGroup{}, err
	}
	anchor := ddaAnchor(req)
	if anchor == "" || len(req.Payments) == 0 {
		return ports.DDAGroup{}, shared.ErrValidation
	}
	for _, pay := range req.Payments {
		if strings.TrimSpace(pay.Content) == "" || pay.AmountCents <= 0 {
			return ports.DDAGroup{}, shared.ErrValidation
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if groupID, ok := s.ddaGroupByIdem[key(tenantID, anchor)]; ok {
		return ports.DDAGroup{ID: groupID}, nil // idempotent re-submit
	}

	groupID := "ddag_" + stubHash(24, tenantID, anchor)
	due := s.now().AddDate(0, 0, 7)
	items := make([]ports.DDAItem, len(req.Payments))
	for i, pay := range req.Payments {
		content := strings.TrimSpace(pay.Content)
		items[i] = ports.DDAItem{
			ID:          "ddai_" + stubHash(20, anchor, content),
			Content:     content,
			AmountCents: pay.AmountCents,
			DueDate:     due,
			Status:      string(dda.StatusReadData),
			ProductType: stubProductType(content),
		}
	}
	s.ddaGroups[key(tenantID, groupID)] = &stubDDAGroup{items: items}
	s.ddaGroupByIdem[key(tenantID, anchor)] = groupID
	return ports.DDAGroup{ID: groupID}, nil
}

// stubProductType classifies a payment reference the way the bank's decode would: an
// all-digit boleto identifier settles a BOLETO, anything else (PIX key, BR Code) a
// PIX.
func stubProductType(content string) string {
	if err := dda.ValidateContent(content); err != nil {
		return ""
	}
	switch len(content) {
	case 44, 47, 48:
		return string(dda.ProductBoleto)
	default:
		return string(dda.ProductPix)
	}
}

// GetPaymentGroup returns the authoritative state of a group (roteiro AP_03 / the read
// the use-case runs before AP_04–AP_06). An unknown group within the tenant is
// shared.ErrNotFound; the read is tenant-scoped so one tenant can never observe
// another's group.
func (s *StubProvider) GetPaymentGroup(ctx context.Context, tenantID, groupID string) (ports.DDAGroup, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.DDAGroup{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ddaGroups[key(tenantID, groupID)]; !ok {
		return ports.DDAGroup{}, shared.ErrNotFound
	}
	return s.toDDAGroup(tenantID, groupID), nil
}

// RemovePaymentGroupItems removes a list of items from a group (roteiro AP_04). An
// unknown group is shared.ErrNotFound; removing an item id not present is a no-op (the
// legality is enforced by the domain in the use-case before this call).
func (s *StubProvider) RemovePaymentGroupItems(ctx context.Context, tenantID, groupID string, itemIDs []string) error {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
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

// RemovePaymentGroupItem removes a single item from a group (roteiro AP_05). It reuses
// the list removal with a one-element list.
func (s *StubProvider) RemovePaymentGroupItem(ctx context.Context, tenantID, groupID, itemID string) error {
	return s.RemovePaymentGroupItems(ctx, tenantID, groupID, []string{itemID})
}

// SubmitPaymentGroup submits a group for approval (roteiro AP_06), flipping every item
// to SCHEDULED — which is how the real API reports a submitted group, there being no
// group-level status. It is idempotent: submitting an already-submitted group
// succeeds. An unknown group is shared.ErrNotFound. uploaderName is required, as in
// the contract; idemKey is accepted for parity with the real adapter (which forwards
// it as Idempotency-Key).
func (s *StubProvider) SubmitPaymentGroup(ctx context.Context, tenantID, groupID, uploaderName, idemKey string) error {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return err
	}
	if strings.TrimSpace(uploaderName) == "" {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.ddaGroups[key(tenantID, groupID)]
	if !ok {
		return shared.ErrNotFound
	}
	for i := range g.items {
		g.items[i].Status = string(dda.StatusScheduled)
	}
	return nil
}

// toDDAGroup snapshots a stored group into a transport DDAGroup with copied items. The
// caller holds s.mu.
func (s *StubProvider) toDDAGroup(tenantID, groupID string) ports.DDAGroup {
	g := s.ddaGroups[key(tenantID, groupID)]
	items := make([]ports.DDAItem, len(g.items))
	copy(items, g.items)
	return ports.DDAGroup{ID: groupID, Items: items}
}
