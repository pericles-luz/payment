// Package dda holds the Agendamento de Pagamentos domain (roteiro grupo AP): the
// boletos a client has open in their DDA (Débito Direto Autorizado) and the
// PaymentGroup aggregate that batches selected payments for an initial consult and
// then for approval. The aggregate OWNS its invariants — that items can no longer be
// removed once the group has been submitted for approval — as PURE domain: it never
// touches the network or the PSP. The C6 adapter only transports the group's
// parameters to the bank; deciding which mutations are legal is the domain's
// responsibility (Hexagonal).
//
// # Por que o vocabulário mudou
//
// Até 21/09/2026 este pacote falava um vocabulário que o banco não tem: um status DE
// GRUPO, com os valores "consultando" e "aprovado". O contrato publicado
// (docs/compliance/c6-schedule-payments-oas.yaml) não expõe status de grupo nenhum —
// quem tem status é o ITEM, e o conjunto é outro (READ_DATA, DECODE_ERROR, ERROR,
// SCHEDULED, PROCESSING, PROCESSED, SCHEDULING_CANCELLED). O status do grupo aqui é
// DERIVADO dos itens, e é o único jeito de a invariante "lote submetido não se edita"
// se apoiar em dado real em vez de numa palavra inventada.
//
// Pela mesma razão o identificador do pagamento deixou de se chamar "barcode": o
// campo do contrato é `content`, e ele aceita código de barras, chave PIX OU BR Code
// — a API agenda "pagamentos de boletos E pixes". Exigir 44/47/48 dígitos recusava
// todo pagamento por PIX, que é metade do produto.
package dda

import (
	"regexp"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// ItemStatus is the lifecycle state of ONE payment inside a group, as the bank
// reports it. It is a closed set taken verbatim from the C6 contract; an unknown
// value is rejected at construction so the aggregate can never hold a state it has
// no rules for.
type ItemStatus string

const (
	// StatusReadData — o item foi cadastrado com sucesso e o lote ainda é editável.
	StatusReadData ItemStatus = "READ_DATA"
	// StatusDecodeError — não foi possível obter informações do pagamento (dados
	// informados inválidos). O item continua no lote e pode ser removido.
	StatusDecodeError ItemStatus = "DECODE_ERROR"
	// StatusError — não foi possível realizar o pagamento.
	StatusError ItemStatus = "ERROR"
	// StatusScheduled — item agendado: o lote já foi submetido.
	StatusScheduled ItemStatus = "SCHEDULED"
	// StatusProcessing — pagamento do item em processamento.
	StatusProcessing ItemStatus = "PROCESSING"
	// StatusProcessed — item pago com sucesso.
	StatusProcessed ItemStatus = "PROCESSED"
	// StatusSchedulingCancelled — agendamento cancelado (depois de submetido).
	StatusSchedulingCancelled ItemStatus = "SCHEDULING_CANCELLED"
)

// ParseItemStatus normalises and validates an item status string (trimmed,
// upper-cased), rejecting anything outside the closed set.
//
// An EMPTY status is accepted as StatusReadData rather than rejected: the create
// (`POST /decode`) response carries only the group_id, so an item built from what we
// submitted has no status yet, and refusing it would make a successful create fail
// validation.
func ParseItemStatus(s string) (ItemStatus, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return StatusReadData, nil
	}
	switch ItemStatus(s) {
	case StatusReadData, StatusDecodeError, StatusError,
		StatusScheduled, StatusProcessing, StatusProcessed, StatusSchedulingCancelled:
		return ItemStatus(s), nil
	default:
		return "", shared.NewValidationError("status", "unknown payment item status")
	}
}

// Submitted reports whether this item's state can only have been reached AFTER the
// group was submitted for approval. It is what the group's freeze invariant reads:
// the bank has no group status, so "já submetido" is inferred from the items it
// actually reports.
func (s ItemStatus) Submitted() bool {
	switch s {
	case StatusScheduled, StatusProcessing, StatusProcessed, StatusSchedulingCancelled:
		return true
	default:
		return false
	}
}

// ProductType is the kind of charge a payment item settles, as the bank reports it.
type ProductType string

const (
	// ProductBoleto is a bank slip payment.
	ProductBoleto ProductType = "BOLETO"
	// ProductPix is a PIX payment.
	ProductPix ProductType = "PIX"
)

// ParseProductType validates the product type, tolerating an empty value (the create
// response does not echo it).
func ParseProductType(s string) (ProductType, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	switch ProductType(s) {
	case ProductBoleto, ProductPix:
		return ProductType(s), nil
	default:
		return "", shared.NewValidationError("product_type", "unknown payment product type")
	}
}

// pixKeyPattern mirrors the `pix_key` pattern in the C6 contract: CPF (11 digits),
// CNPJ (14 digits), phone (+E.164), e-mail, or EVP (UUID). It is a SYNTACTIC check —
// whether the key exists is the DICT's answer, not ours.
var pixKeyPattern = regexp.MustCompile(
	`^(?:[0-9]{11}|[0-9]{14}|\+[1-9][0-9][0-9]{5,14}|` +
		`[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}|` +
		`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

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

// validBRCode reports whether s looks like a BR Code (o "pix copia e cola"): the EMV
// payload-format-indicator prefix plus the contract's length bounds. Checking the
// prefix and not only the length is what keeps a 60-character typo from passing as a
// payment instruction.
func validBRCode(s string) bool {
	return len(s) >= 32 && len(s) <= 396 && strings.HasPrefix(s, "0002")
}

// ValidateContent reports whether a payment reference submitted into a group
// (roteiro AP_01) is syntactically addressable: a boleto barcode / linha digitável, a
// PIX key, or a BR Code. It is exported so the use-case can validate submissions at
// its boundary before the group exists.
func ValidateContent(content string) error {
	content = strings.TrimSpace(content)
	if validBarcode(content) || validBRCode(content) || pixKeyPattern.MatchString(content) {
		return nil
	}
	return shared.NewValidationError("content",
		"content must be a boleto barcode, a PIX key or a BR Code")
}

// DDABoleto is one boleto open in a client's DDA (roteiro AP_02, the `bonds` schema):
// the reference to pay, the amount, the due date and whether it is overdue, plus the
// beneficiary and payer names. It is a read projection; immutable once built.
//
// It carries NO id, because the contract's `bonds` has none — a DDA bond is addressed
// by its `content`, which is what `POST /decode` takes. The previous shape had an id
// field that no response could ever fill.
type DDABoleto struct {
	content         string
	amountCents     int64
	dueDate         time.Time
	beneficiaryName string
	payerName       string
	bankCode        string
	bankName        string
	overdue         bool
}

// DDABoletoParams carries the fields of a DDA bond read back from the bank. It is a
// parameter object rather than a long positional argument list: eight positional
// strings and bools would be trivially transposable at the call site, and two of them
// are names that would swap silently.
type DDABoletoParams struct {
	Content         string
	AmountCents     int64
	DueDate         time.Time
	BeneficiaryName string
	PayerName       string
	BankCode        string
	BankName        string
	Overdue         bool
}

// NewDDABoleto builds a DDABoleto, validating the payment reference, a positive
// amount and a real due date. The beneficiary name is required; the payer name, bank
// code and bank name are informative and optional.
func NewDDABoleto(p DDABoletoParams) (DDABoleto, error) {
	content := strings.TrimSpace(p.Content)
	if err := ValidateContent(content); err != nil {
		return DDABoleto{}, err
	}
	if p.AmountCents <= 0 {
		return DDABoleto{}, shared.NewValidationError("boleto.amount", "amount must be greater than zero")
	}
	if p.DueDate.IsZero() {
		return DDABoleto{}, shared.NewValidationError("boleto.due_date", "due date is required")
	}
	beneficiaryName := strings.TrimSpace(p.BeneficiaryName)
	if beneficiaryName == "" {
		return DDABoleto{}, shared.NewValidationError("boleto.beneficiary_name", "beneficiary name is required")
	}
	return DDABoleto{
		content:         content,
		amountCents:     p.AmountCents,
		dueDate:         p.DueDate,
		beneficiaryName: beneficiaryName,
		payerName:       strings.TrimSpace(p.PayerName),
		bankCode:        strings.TrimSpace(p.BankCode),
		bankName:        strings.TrimSpace(p.BankName),
		overdue:         p.Overdue,
	}, nil
}

// Content returns the payment reference (barcode, PIX key or BR Code).
func (b DDABoleto) Content() string { return b.content }

// AmountCents returns the boleto amount in cents.
func (b DDABoleto) AmountCents() int64 { return b.amountCents }

// DueDate returns the boleto due date.
func (b DDABoleto) DueDate() time.Time { return b.dueDate }

// BeneficiaryName returns the beneficiary's name.
func (b DDABoleto) BeneficiaryName() string { return b.beneficiaryName }

// PayerName returns the payer's (sacado's) name.
func (b DDABoleto) PayerName() string { return b.payerName }

// BankCode returns the issuing bank's code.
func (b DDABoleto) BankCode() string { return b.bankCode }

// BankName returns the issuing bank's name.
func (b DDABoleto) BankName() string { return b.bankName }

// Overdue reports whether the bond is past its due date.
func (b DDABoleto) Overdue() bool { return b.overdue }

// Item is one payment line in a payment group: the bank's item id, the payment
// reference, the amount, and the state the bank reports for it. Immutable once built.
type Item struct {
	id           string
	content      string
	amountCents  int64
	dueDate      time.Time
	status       ItemStatus
	productType  ProductType
	errorMessage string
	overdue      bool
}

// ItemParams carries the fields of a group item read back from the bank. Same reason
// for being a parameter object as DDABoletoParams.
type ItemParams struct {
	ID           string
	Content      string
	AmountCents  int64
	DueDate      time.Time
	Status       string
	ProductType  string
	ErrorMessage string
	Overdue      bool
}

// NewItem builds a group Item, validating the item id, the payment reference, a
// positive amount and the reported status.
//
// The due date is NOT required here, unlike on a DDA bond: a PIX item has no due date
// at all, and the contract marks `due_date` readOnly and optional on `payment`.
func NewItem(p ItemParams) (Item, error) {
	id := strings.TrimSpace(p.ID)
	if id == "" {
		return Item{}, shared.NewValidationError("item.id", "item id is required")
	}
	content := strings.TrimSpace(p.Content)
	if err := ValidateContent(content); err != nil {
		return Item{}, err
	}
	if p.AmountCents <= 0 {
		return Item{}, shared.NewValidationError("item.amount", "amount must be greater than zero")
	}
	status, err := ParseItemStatus(p.Status)
	if err != nil {
		return Item{}, err
	}
	product, err := ParseProductType(p.ProductType)
	if err != nil {
		return Item{}, err
	}
	return Item{
		id:           id,
		content:      content,
		amountCents:  p.AmountCents,
		dueDate:      p.DueDate,
		status:       status,
		productType:  product,
		errorMessage: strings.TrimSpace(p.ErrorMessage),
		overdue:      p.Overdue,
	}, nil
}

// ID returns the item id.
func (i Item) ID() string { return i.id }

// Content returns the item's payment reference.
func (i Item) Content() string { return i.content }

// AmountCents returns the item amount in cents.
func (i Item) AmountCents() int64 { return i.amountCents }

// DueDate returns the item due date (zero for a payment that has none).
func (i Item) DueDate() time.Time { return i.dueDate }

// Status returns the state the bank reports for this item.
func (i Item) Status() ItemStatus { return i.status }

// ProductType returns whether the item settles a boleto or a PIX (empty when the bank
// has not resolved it yet).
func (i Item) ProductType() ProductType { return i.productType }

// ErrorMessage returns the bank's processing error for this item, empty when none.
func (i Item) ErrorMessage() string { return i.errorMessage }

// Overdue reports whether the item's charge is past its due date.
func (i Item) Overdue() bool { return i.overdue }

// PaymentGroup is a payment group aggregate: a batch of payment items. It is the
// authority over which mutations are legal — items may be removed only while the
// group has not been submitted; once submitted it is frozen, exactly as the C6
// contract states ("a partir deste momento não é mais possível a edição do lote via
// API").
//
// It holds NO status field of its own: see the package comment.
type PaymentGroup struct {
	id       string
	tenantID string
	items    []Item
}

// Reconstruct rebuilds a PaymentGroup from authoritative state read back from the
// PSP so the use-case can enforce a mutation against the real current state. The id
// and tenant are validated; the items are taken as-is (already validated when each
// Item was constructed).
func Reconstruct(id, tenantID string, items []Item) (PaymentGroup, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return PaymentGroup{}, shared.NewValidationError("group.id", "group id is required")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PaymentGroup{}, shared.NewValidationError("group.tenant_id", "tenant id is required")
	}
	owned := make([]Item, len(items))
	copy(owned, items)
	return PaymentGroup{id: id, tenantID: tenantID, items: owned}, nil
}

// ID returns the group identifier.
func (g *PaymentGroup) ID() string { return g.id }

// TenantID returns the owning tenant.
func (g *PaymentGroup) TenantID() string { return g.tenantID }

// Items returns a copy of the group's items.
func (g *PaymentGroup) Items() []Item {
	out := make([]Item, len(g.items))
	copy(out, g.items)
	return out
}

// IsSubmitted reports whether the group has already gone for approval, derived from
// the item states the bank reports. A re-submit of an already-submitted group is a
// no-op (idempotent), distinct from an illegal transition.
//
// An EMPTY group is not submitted: it has no evidence either way, and answering
// "submitted" would let SubmitForApproval's empty-group guard be skipped.
func (g *PaymentGroup) IsSubmitted() bool {
	for _, it := range g.items {
		if it.status.Submitted() {
			return true
		}
	}
	return false
}

// RemoveItems removes the items with the given ids (roteiro AP_04 a list, AP_05 a
// single id passed as a one-element list). It enforces the core invariant: a
// submitted group is frozen, so removing from it is an illegal transition
// (shared.ErrInvalidTransition). At least one id must be supplied, and every id must
// currently belong to the group — an unknown id is shared.ErrNotFound (no silent
// partial removal).
func (g *PaymentGroup) RemoveItems(ids ...string) error {
	if g.IsSubmitted() {
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

// SubmitForApproval marks the group as gone for approval (roteiro AP_06). Only a
// group that has not been submitted may be submitted; any other source state is an
// illegal transition (shared.ErrInvalidTransition). A group with no items cannot be
// submitted.
//
// The local state change is bookkeeping for the caller within one request: the
// authoritative answer is always re-read from the bank, which is why IsSubmitted is
// derived from item state rather than from a flag we set here.
func (g *PaymentGroup) SubmitForApproval() error {
	if g.IsSubmitted() {
		return shared.ErrInvalidTransition
	}
	if len(g.items) == 0 {
		return shared.NewValidationError("items", "cannot submit an empty payment group")
	}
	for i := range g.items {
		g.items[i].status = StatusScheduled
	}
	return nil
}
