package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/dda"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// maxDDAGroupBarcodes bounds how many boletos a single consult submission may carry
// (defense-in-depth with the HTTP body cap): an unbounded list would push an
// arbitrarily large batch to the PSP.
const maxDDAGroupBarcodes = 200

// DDAService orchestrates the DDA / agendamento de pagamentos surface (roteiro grupo
// 8): list the boletos open in a tenant's DDA, batch selected boletos into a payment
// group for the initial consult, read/trim the group and submit it for approval.
//
// It is intentionally NOT a billable charge-creation use-case (no payment/ledger): a
// DDA group is a scheduling/consult artifact at the bank, not a charge the platform
// originates and prices. The transition rules (a group may be trimmed only while
// consulting; once approved it is frozen) live in the dda.PaymentGroup aggregate; this
// service reads the authoritative state from the provider and lets the aggregate
// decide before applying any mutation. The tenant is ALWAYS the authenticated tenant,
// never client input (threat H1/P1); an id owned by another tenant surfaces as
// not-found (no cross-tenant existence oracle).
type DDAService struct {
	tenants ports.TenantRepository
	dda     ports.DDAProvider
}

// NewDDAService wires a DDAService from the provided ports.
func NewDDAService(d Deps) *DDAService {
	return &DDAService{tenants: d.Tenants, dda: d.DDA}
}

// CreateGroupInput is the validated boundary input to submit a payment group for the
// initial consult (roteiro 8.2). TenantID is the authenticated tenant; Barcodes are
// the boletos selected into the group; the Idempotency key is mandatory (write).
type CreateGroupInput struct {
	TenantID       string
	Barcodes       []string
	IdempotencyKey string
}

// requireActiveTenant resolves the authenticated tenant and asserts it is active. It
// is the common deny-by-default guard every DDA operation runs first.
func (s *DDAService) requireActiveTenant(ctx context.Context, tenantID string) error {
	t, err := s.tenants.FindTenantByID(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("resolve tenant: %w", err)
	}
	if !t.Active() {
		return shared.NewValidationError("tenant", "tenant is not active")
	}
	return nil
}

// ListOpenBoletos returns the boletos open in the authenticated tenant's DDA (roteiro
// 8.1).
func (s *DDAService) ListOpenBoletos(ctx context.Context, tenantID string) ([]ports.DDABoleto, error) {
	if err := s.requireActiveTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	return s.dda.ListOpenBoletos(ctx, tenantID)
}

// CreatePaymentGroup submits the selected boletos for the initial consult (roteiro
// 8.2) and returns the resulting consultando group. The barcodes are validated at the
// boundary (at least one, each syntactically a boleto identifier, count bounded) and
// the returned group is validated through the domain so an inconsistent PSP response
// is rejected rather than surfaced. Retrying with the same idempotency key resolves to
// the original group without creating a duplicate (the provider collapses on the key).
func (s *DDAService) CreatePaymentGroup(ctx context.Context, in CreateGroupInput) (ports.DDAGroup, error) {
	if err := s.requireActiveTenant(ctx, in.TenantID); err != nil {
		return ports.DDAGroup{}, err
	}
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return ports.DDAGroup{}, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	if len(in.Barcodes) == 0 {
		return ports.DDAGroup{}, shared.NewValidationError("barcodes", "at least one boleto barcode is required")
	}
	if len(in.Barcodes) > maxDDAGroupBarcodes {
		return ports.DDAGroup{}, shared.NewValidationError("barcodes", "too many boletos in a single group")
	}
	barcodes := make([]string, len(in.Barcodes))
	for i, bc := range in.Barcodes {
		if err := dda.ValidateBarcode(bc); err != nil {
			return ports.DDAGroup{}, err
		}
		barcodes[i] = strings.TrimSpace(bc)
	}

	group, err := s.dda.CreatePaymentGroup(ctx, in.TenantID, ports.DDAGroupRequest{
		TenantID:       in.TenantID,
		Barcodes:       barcodes,
		IdempotencyKey: in.IdempotencyKey,
	})
	if err != nil {
		return ports.DDAGroup{}, fmt.Errorf("bank create payment group: %w", err)
	}
	// Validate the PSP response through the domain (status known, items well-formed)
	// so an inconsistent group never reaches the caller.
	if _, err := s.reconstruct(in.TenantID, group); err != nil {
		return ports.DDAGroup{}, err
	}
	return group, nil
}

// GetPaymentGroupItems reconciles a group's items for the authenticated tenant
// (roteiro 8.3). An id owned by another tenant — like an unknown id — is not-found.
func (s *DDAService) GetPaymentGroupItems(ctx context.Context, tenantID, groupID string) ([]ports.DDAItem, error) {
	if err := s.requireActiveTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return nil, shared.NewValidationError("group_id", "group id is required")
	}
	group, err := s.dda.GetPaymentGroup(ctx, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	return group.Items, nil
}

// RemovePaymentGroupItems removes a list of items from a group (roteiro 8.4). It reads
// the authoritative state, lets the domain aggregate decide whether the removal is
// legal (a frozen/approved group is rejected, an unknown item id is not-found), then
// applies it at the PSP.
func (s *DDAService) RemovePaymentGroupItems(ctx context.Context, tenantID, groupID string, itemIDs []string) error {
	group, err := s.loadForMutation(ctx, tenantID, groupID)
	if err != nil {
		return err
	}
	if len(itemIDs) == 0 {
		return shared.NewValidationError("item_ids", "at least one item id is required")
	}
	if err := group.RemoveItems(itemIDs...); err != nil {
		return err
	}
	return s.dda.RemovePaymentGroupItems(ctx, tenantID, groupID, itemIDs)
}

// RemovePaymentGroupItem removes a single item from a group (roteiro 8.5). Same
// read-validate-apply flow as RemovePaymentGroupItems with a one-element list.
func (s *DDAService) RemovePaymentGroupItem(ctx context.Context, tenantID, groupID, itemID string) error {
	group, err := s.loadForMutation(ctx, tenantID, groupID)
	if err != nil {
		return err
	}
	itemID = strings.TrimSpace(itemID)
	if itemID == "" {
		return shared.NewValidationError("item_id", "item id is required")
	}
	if err := group.RemoveItems(itemID); err != nil {
		return err
	}
	return s.dda.RemovePaymentGroupItem(ctx, tenantID, groupID, itemID)
}

// SubmitPaymentGroup submits a consulting group for approval (roteiro 8.6). The
// Idempotency-Key header is mandatory (write). Submitting an already-approved group is
// an idempotent no-op (success); submitting a group in any non-consulting state is an
// illegal transition the domain rejects. The key is forwarded as defense-in-depth so a
// retried submit collapses at the PSP too.
func (s *DDAService) SubmitPaymentGroup(ctx context.Context, tenantID, groupID, idemKey string) error {
	if strings.TrimSpace(idemKey) == "" {
		return shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	group, err := s.loadForMutation(ctx, tenantID, groupID)
	if err != nil {
		return err
	}
	if group.IsApproved() {
		// Resource is already in the target state: a retried/duplicate submit is a
		// no-op success (idempotent), not an error.
		return nil
	}
	if err := group.SubmitForApproval(); err != nil {
		return err
	}
	return s.dda.SubmitPaymentGroup(ctx, tenantID, groupID, idemKey)
}

// loadForMutation runs the active-tenant guard, validates the group id, reads the
// authoritative group state from the provider and rebuilds the domain aggregate. It is
// the shared prologue of every group mutation (8.4/8.5/8.6).
func (s *DDAService) loadForMutation(ctx context.Context, tenantID, groupID string) (*dda.PaymentGroup, error) {
	if err := s.requireActiveTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return nil, shared.NewValidationError("group_id", "group id is required")
	}
	group, err := s.dda.GetPaymentGroup(ctx, tenantID, groupID)
	if err != nil {
		return nil, err
	}
	return s.reconstruct(tenantID, group)
}

// reconstruct maps a transported group onto the domain aggregate, mapping each
// transport item through the domain item constructor so a malformed PSP response is
// rejected (defense in depth at the trust boundary).
func (s *DDAService) reconstruct(tenantID string, group ports.DDAGroup) (*dda.PaymentGroup, error) {
	status, err := dda.ParseGroupStatus(group.Status)
	if err != nil {
		return nil, err
	}
	items := make([]dda.Item, 0, len(group.Items))
	for _, it := range group.Items {
		di, err := dda.NewItem(it.ID, it.Barcode, it.AmountCents, it.DueDate)
		if err != nil {
			return nil, err
		}
		items = append(items, di)
	}
	pg, err := dda.Reconstruct(group.ID, tenantID, status, items)
	if err != nil {
		return nil, err
	}
	return &pg, nil
}
