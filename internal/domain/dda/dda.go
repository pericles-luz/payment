// Package dda holds the DDA / Agendamento de Pagamentos domain (roteiro grupo 8):
// the boletos a client has open in their DDA (Débito Direto Autorizado) and the
// PaymentGroup aggregate that batches selected payments for an initial consult and
// then for approval. The aggregate OWNS its invariants — the legal status
// transitions (consultando → aprovado) and the rule that items can no longer be
// removed once the group has been submitted for approval — as PURE domain: it never
// touches the network or the PSP. The C6 adapter only transports the group's
// parameters to the bank; deciding which transitions are legal is the domain's
// responsibility (Hexagonal).
package dda

import (
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// GroupStatus is the lifecycle state of a DDA payment group. It is a closed set; an
// unknown value is rejected at construction so the aggregate can never hold a state
// it has no rules for.
type GroupStatus string

const (
	// StatusConsulting is the state right after the initial consult is submitted
	// (roteiro 8.2): items may still be removed (8.4/8.5) and the group may be
	// submitted for approval (8.6).
	StatusConsulting GroupStatus = "consultando"
	// StatusApproved is the state after the group is submitted for approval (roteiro
	// 8.6): the group is frozen — its items can no longer be removed.
	StatusApproved GroupStatus = "aprovado"
)

// ParseGroupStatus normalises and validates a status string (trimmed), rejecting
// anything outside the closed set.
func ParseGroupStatus(s string) (GroupStatus, error) {
	switch GroupStatus(strings.TrimSpace(s)) {
	case StatusConsulting:
		return StatusConsulting, nil
	case StatusApproved:
		return StatusApproved, nil
	default:
		return "", shared.NewValidationError("status", "unknown payment group status")
	}
}

// validBarcode reports whether s is an all-digit boleto identifier: a código de
// barras (44 digits) or a linha digitável (47 for cobrança, 48 for arrecadação). It
// is a syntactic check (length + digits), not a check-digit validation.
func validBarcode(s string) bool {
	switch len(s) {
	case 44, 47, 48:
	default:
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ValidateBarcode reports whether a barcode submitted into a group (roteiro 8.2) is
// syntactically a boleto identifier. It is exported so the use-case can validate the
// submitted barcodes at its boundary before the group exists.
func ValidateBarcode(barcode string) error {
	if !validBarcode(strings.TrimSpace(barcode)) {
		return shared.NewValidationError("barcode", "barcode must be a 44, 47 or 48 digit boleto identifier")
	}
	return nil
}

// DDABoleto is one boleto open in a client's DDA (roteiro 8.1): its bank id, the
// scannable barcode / linha digitável, the amount and the due date plus the
// beneficiary's name. It is a read projection; immutable once built.
type DDABoleto struct {
	id              string
	barcode         string
	amountCents     int64
	dueDate         time.Time
	beneficiaryName string
}

// NewDDABoleto builds a DDABoleto, validating the bank id, barcode, a positive
// amount and a real due date. The beneficiary name is required.
func NewDDABoleto(id, barcode string, amountCents int64, dueDate time.Time, beneficiaryName string) (DDABoleto, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return DDABoleto{}, shared.NewValidationError("boleto.id", "boleto id is required")
	}
	barcode = strings.TrimSpace(barcode)
	if !validBarcode(barcode) {
		return DDABoleto{}, shared.NewValidationError("boleto.barcode", "barcode must be a 44, 47 or 48 digit boleto identifier")
	}
	if amountCents <= 0 {
		return DDABoleto{}, shared.NewValidationError("boleto.amount_cents", "amount must be greater than zero")
	}
	if dueDate.IsZero() {
		return DDABoleto{}, shared.NewValidationError("boleto.due_date", "due date is required")
	}
	beneficiaryName = strings.TrimSpace(beneficiaryName)
	if beneficiaryName == "" {
		return DDABoleto{}, shared.NewValidationError("boleto.beneficiary_name", "beneficiary name is required")
	}
	return DDABoleto{id: id, barcode: barcode, amountCents: amountCents, dueDate: dueDate, beneficiaryName: beneficiaryName}, nil
}

// ID returns the bank id of the open boleto.
func (b DDABoleto) ID() string { return b.id }

// Barcode returns the scannable barcode / linha digitável.
func (b DDABoleto) Barcode() string { return b.barcode }

// AmountCents returns the boleto amount in cents.
func (b DDABoleto) AmountCents() int64 { return b.amountCents }

// DueDate returns the boleto due date.
func (b DDABoleto) DueDate() time.Time { return b.dueDate }

// BeneficiaryName returns the beneficiary's name.
func (b DDABoleto) BeneficiaryName() string { return b.beneficiaryName }

// Item is one payment line in a DDA payment group: a boleto identified by the bank's
// item id and its barcode, with the amount and due date the bank resolved. Immutable
// once built.
type Item struct {
	id          string
	barcode     string
	amountCents int64
	dueDate     time.Time
}

// NewItem builds a group Item, validating the item id, barcode, a positive amount
// and a real due date.
func NewItem(id, barcode string, amountCents int64, dueDate time.Time) (Item, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Item{}, shared.NewValidationError("item.id", "item id is required")
	}
	barcode = strings.TrimSpace(barcode)
	if !validBarcode(barcode) {
		return Item{}, shared.NewValidationError("item.barcode", "barcode must be a 44, 47 or 48 digit boleto identifier")
	}
	if amountCents <= 0 {
		return Item{}, shared.NewValidationError("item.amount_cents", "amount must be greater than zero")
	}
	if dueDate.IsZero() {
		return Item{}, shared.NewValidationError("item.due_date", "due date is required")
	}
	return Item{id: id, barcode: barcode, amountCents: amountCents, dueDate: dueDate}, nil
}

// ID returns the item id.
func (i Item) ID() string { return i.id }

// Barcode returns the item's boleto barcode.
func (i Item) Barcode() string { return i.barcode }

// AmountCents returns the item amount in cents.
func (i Item) AmountCents() int64 { return i.amountCents }

// DueDate returns the item due date.
func (i Item) DueDate() time.Time { return i.dueDate }

// PaymentGroup is a DDA payment group aggregate: a batch of boleto payment items in
// a lifecycle state. It is the authority over which mutations are legal — items may
// be removed only while the group is still consulting; once approved it is frozen.
type PaymentGroup struct {
	id       string
	tenantID string
	status   GroupStatus
	items    []Item
}

// Reconstruct rebuilds a PaymentGroup from authoritative state read back from the
// PSP so the use-case can enforce a transition against the real current state. The
// id, tenant and status are validated; the items are taken as-is (already validated
// when each Item was constructed). At least the identifiers must be present.
func Reconstruct(id, tenantID string, status GroupStatus, items []Item) (PaymentGroup, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return PaymentGroup{}, shared.NewValidationError("group.id", "group id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PaymentGroup{}, shared.NewValidationError("group.tenant_id", "tenant id is required")
	}
	if _, err := ParseGroupStatus(string(status)); err != nil {
		return PaymentGroup{}, err
	}
	owned := make([]Item, len(items))
	copy(owned, items)
	return PaymentGroup{id: id, tenantID: tenantID, status: status, items: owned}, nil
}

// ID returns the group identifier.
func (g *PaymentGroup) ID() string { return g.id }

// TenantID returns the owning tenant.
func (g *PaymentGroup) TenantID() string { return g.tenantID }

// Status returns the lifecycle state.
func (g *PaymentGroup) Status() GroupStatus { return g.status }

// IsApproved reports whether the group has already been submitted for approval. A
// re-submit of an already-approved group is a no-op (idempotent), distinct from an
// illegal transition.
func (g *PaymentGroup) IsApproved() bool { return g.status == StatusApproved }

// Items returns a copy of the group's items.
func (g *PaymentGroup) Items() []Item {
	out := make([]Item, len(g.items))
	copy(out, g.items)
	return out
}

// RemoveItems removes the items with the given ids (roteiro 8.4 a list, 8.5 a single
// id passed as a one-element list). It enforces the core invariant: an approved group
// is frozen, so removing from it is an illegal transition (shared.ErrInvalidTransition).
// At least one id must be supplied, and every id must currently belong to the group —
// an unknown id is shared.ErrNotFound (no silent partial removal).
func (g *PaymentGroup) RemoveItems(ids ...string) error {
	if g.status == StatusApproved {
		return shared.ErrInvalidTransition
	}
	if len(ids) == 0 {
		return shared.NewValidationError("item_ids", "at least one item id is required")
	}
	// Validate every id exists before mutating so the removal is all-or-nothing.
	present := make(map[string]bool, len(g.items))
	for _, it := range g.items {
		present[it.id] = true
	}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			return shared.NewValidationError("item_id", "item id must not be empty")
		}
		if !present[id] {
			return shared.ErrNotFound
		}
	}
	remove := make(map[string]bool, len(ids))
	for _, id := range ids {
		remove[strings.TrimSpace(id)] = true
	}
	kept := g.items[:0:0]
	for _, it := range g.items {
		if !remove[it.id] {
			kept = append(kept, it)
		}
	}
	g.items = kept
	return nil
}

// SubmitForApproval transitions the group from consultando to aprovado (roteiro 8.6).
// Only a consulting group may be submitted; any other source state is an illegal
// transition (shared.ErrInvalidTransition). A group with no items cannot be submitted.
func (g *PaymentGroup) SubmitForApproval() error {
	if g.status != StatusConsulting {
		return shared.ErrInvalidTransition
	}
	if len(g.items) == 0 {
		return shared.NewValidationError("items", "cannot submit an empty payment group")
	}
	g.status = StatusApproved
	return nil
}
