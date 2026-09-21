package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/dda"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// maxDDAGroupPayments bounds how many payments a single consult submission may carry
// (defense-in-depth with the HTTP body cap): an unbounded list would push an
// arbitrarily large batch to the PSP.
const maxDDAGroupPayments = 200

// maxDDADescriptionLen is the contract's ceiling on a payment description (100
// characters). It is checked HERE rather than left to the bank because the field is
// shown on the approval screen and a 400 from the PSP for a too-long description
// would surface as an opaque failure of the whole batch.
const maxDDADescriptionLen = 100

// DDAService orchestrates the Agendamento de Pagamentos surface (roteiro grupo AP):
// list the bonds open in a tenant's DDA, batch selected payments into a group for the
// initial consult, read/trim the group and submit it for approval.
//
// It is intentionally NOT a billable charge-creation use-case (no payment/ledger): a
// payment group is a scheduling/consult artifact at the bank, not a charge the
// platform originates and prices. The freeze rule (a group may be trimmed only until
// it is submitted) lives in the dda.PaymentGroup aggregate; this
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
// initial consult (roteiro AP_01). TenantID is the authenticated tenant; Payments are
// the boletos/pixes selected into the group; the Idempotency key is mandatory (write).
type CreateGroupInput struct {
	TenantID       string
	Payments       []ports.DDAPayment
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

// ListOpenBoletos returns the bonds open in the authenticated tenant's DDA (roteiro
// AP_02).
func (s *DDAService) ListOpenBoletos(ctx context.Context, tenantID string) ([]ports.DDABoleto, error) {
	if err := s.requireActiveTenant(ctx, tenantID); err != nil {
		return nil, err
	}
	return s.dda.ListOpenBoletos(ctx, tenantID)
}

// CreatePaymentGroup submits the selected payments for the initial consult (roteiro
// AP_01) and returns the new group's id. The payments are validated at the boundary
// (at least one, each with an addressable reference and a positive amount, count and
// description bounded).
//
// The bank answers with the group id ALONE, so there is nothing to reconstruct
// through the domain here: the items only exist once they are read back (AP_03). What
// IS checked is that an id came back at all — an empty id would surface as a
// not-found on the caller's next call, pointing at the wrong place.
func (s *DDAService) CreatePaymentGroup(ctx context.Context, in CreateGroupInput) (ports.DDAGroup, error) {
	if err := s.requireActiveTenant(ctx, in.TenantID); err != nil {
		return ports.DDAGroup{}, err
	}
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return ports.DDAGroup{}, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	if len(in.Payments) == 0 {
		return ports.DDAGroup{}, shared.NewValidationError("payments", "at least one payment is required")
	}
	if len(in.Payments) > maxDDAGroupPayments {
		return ports.DDAGroup{}, shared.NewValidationError("payments", "too many payments in a single group")
	}
	payments := make([]ports.DDAPayment, len(in.Payments))
	for i, pay := range in.Payments {
		if err := dda.ValidateContent(pay.Content); err != nil {
			return ports.DDAGroup{}, err
		}
		if pay.AmountCents <= 0 {
			return ports.DDAGroup{}, shared.NewValidationError("amount", "amount must be greater than zero")
		}
		if len(pay.Description) > maxDDADescriptionLen {
			return ports.DDAGroup{}, shared.NewValidationError("description", "description is too long")
		}
		pay.Content = strings.TrimSpace(pay.Content)
		payments[i] = pay
	}

	group, err := s.dda.CreatePaymentGroup(ctx, in.TenantID, ports.DDAGroupRequest{
		TenantID:       in.TenantID,
		Payments:       payments,
		IdempotencyKey: in.IdempotencyKey,
	})
	if err != nil {
		return ports.DDAGroup{}, fmt.Errorf("bank create payment group: %w", err)
	}
	if strings.TrimSpace(group.ID) == "" {
		return ports.DDAGroup{}, shared.NewValidationError("group.id", "bank returned no payment group id")
	}
	return group, nil
}

// GetPaymentGroupItems reconciles a group's items for the authenticated tenant
// (roteiro AP_03). An id owned by another tenant — like an unknown id — is not-found.
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

// RemovePaymentGroupItems removes a list of items from a group (roteiro AP_04). It
// reads the authoritative state, lets the domain aggregate decide whether the removal
// is legal (a submitted group is frozen, an unknown item id is not-found), then
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

// RemovePaymentGroupItem removes a single item from a group (roteiro AP_05). Same
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

// SubmitPaymentGroup submits a group for approval (roteiro AP_06). The
// Idempotency-Key header is mandatory (write) and uploaderName — the operator the
// bank shows on its approval screen — is required by the contract. Submitting an
// already-submitted group is an idempotent no-op (success). The key is forwarded as
// defense-in-depth so a retried submit collapses at the PSP too.
func (s *DDAService) SubmitPaymentGroup(ctx context.Context, tenantID, groupID, uploaderName, idemKey string) error {
	if strings.TrimSpace(idemKey) == "" {
		return shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	if strings.TrimSpace(uploaderName) == "" {
		return shared.NewValidationError("uploader_name", "uploader name is required")
	}
	group, err := s.loadForMutation(ctx, tenantID, groupID)
	if err != nil {
		return err
	}
	if group.IsSubmitted() {
		// Resource is already in the target state: a retried/duplicate submit is a
		// no-op success (idempotent), not an error.
		return nil
	}
	if err := group.SubmitForApproval(); err != nil {
		return err
	}
	return s.dda.SubmitPaymentGroup(ctx, tenantID, groupID, uploaderName, idemKey)
}

// loadForMutation runs the active-tenant guard, validates the group id, reads the
// authoritative group state from the provider and rebuilds the domain aggregate. It is
// the shared prologue of every group mutation (AP_04/AP_05/AP_06).
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
	items := make([]dda.Item, 0, len(group.Items))
	for _, it := range group.Items {
		di, err := dda.NewItem(dda.ItemParams{
			ID:           it.ID,
			Content:      it.Content,
			AmountCents:  it.AmountCents,
			DueDate:      it.DueDate,
			Status:       it.Status,
			ProductType:  it.ProductType,
			ErrorMessage: it.ErrorMessage,
			Overdue:      it.Overdue,
		})
		if err != nil {
			return nil, err
		}
		items = append(items, di)
	}
	pg, err := dda.Reconstruct(group.ID, tenantID, items)
	if err != nil {
		return nil, err
	}
	return &pg, nil
}
