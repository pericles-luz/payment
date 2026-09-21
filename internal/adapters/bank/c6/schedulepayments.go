package c6

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Agendamento de Pagamentos (roteiro grupo AP) for the C6 adapter.
//
// The lifecycle: CreatePaymentGroup submits the selected payments for the initial
// consult and gets back a group_id; GetPaymentGroup reconciles the authoritative item
// state (the source of truth the use-case reads before trimming/submitting); the
// remove and submit operations mutate the group. All of it lives here so the
// use-cases never speak HTTP/JSON or know the PSP wire shape (Hexagonal).
//
// # Este arquivo substitui o `dda.go`, e o motivo importa
//
// O anterior chamava `/v1/dda/boletos` e `/v1/dda/payment-groups`, com um corpo
// inventado ("the adapter's clean internal contract (snake_case, explicit
// cents/ids)"), e dizia que a tradução para o fio real viria depois. Ela nunca veio, e
// o 404 que o banco devolvia foi lido como "esta conta não tem DDA" — está assim na
// ADR-0013. Não era: nenhum desses caminhos existe em contrato nenhum. O produto é
// `/v1/schedule_payments/`, publicado em `/apis/schedule-payments` desde antes do
// primeiro baseline do portal.
//
// As formas abaixo saem do contrato oficial versionado em
// docs/compliance/c6-schedule-payments-oas.yaml (OAS 3.0.3, v1.1.0), não de
// adivinhação.

// schedulePaymentsPath is the C6 Agendamento de Pagamentos collection. Note it is a
// SIBLING of the group id, not a parent of it: the remove/read operations hang off
// /{group_id}/items while submit is the collection-level /submit carrying the group
// id in the BODY.
const schedulePaymentsPath = "/v1/schedule_payments"

// compile-time assertion that Provider satisfies the Agendamento port.
var _ ports.DDAProvider = (*Provider)(nil)

// schedulePaymentBody is one payment SENT to /decode. Only content and amount are
// required by the contract; the rest is informative and shows up on the approval
// screen in the bank's web banking. The date layout is the contract's `format: date`
// (YYYY-MM-DD), not RFC3339.
type schedulePaymentBody struct {
	Amount          brlDecimal `json:"amount"`
	BankCode        string     `json:"bank_code,omitempty"`
	BankName        string     `json:"bank_name,omitempty"`
	BeneficiaryName string     `json:"beneficiary_name,omitempty"`
	Content         string     `json:"content"`
	Description     string     `json:"description,omitempty"`
	PayerName       string     `json:"payer_name,omitempty"`
	TransactionDate string     `json:"transaction_date,omitempty"`
}

// scheduleDecodeRequestBody wraps the payments submitted for the initial consult.
type scheduleDecodeRequestBody struct {
	Items []schedulePaymentBody `json:"items"`
}

// scheduleDecodeResponseBody is the whole 201 body: the group id, and nothing else.
type scheduleDecodeResponseBody struct {
	GroupID string `json:"group_id"`
}

// schedulePaymentView is one payment READ BACK from /{group_id}/items. It is the
// `payment` schema with its readOnly fields populated — the id, the resolved state
// and any processing error.
type schedulePaymentView struct {
	Amount          brlDecimal `json:"amount"`
	BankCode        string     `json:"bank_code"`
	BankName        string     `json:"bank_name"`
	BeneficiaryName string     `json:"beneficiary_name"`
	Content         string     `json:"content"`
	Description     string     `json:"description"`
	DueDate         string     `json:"due_date"`
	ErrorMessage    string     `json:"error_message"`
	GroupID         string     `json:"group_id"`
	ID              string     `json:"id"`
	Overdue         bool       `json:"overdue"`
	PayerName       string     `json:"payer_name"`
	ProductType     string     `json:"product_type"`
	Status          string     `json:"status"`
	TransactionDate string     `json:"transaction_date"`
}

// scheduleItemsResponseBody wraps the items of a group.
type scheduleItemsResponseBody struct {
	Items []schedulePaymentView `json:"items"`
}

// scheduleBondView is one open DDA bond read from /query (the `bonds` schema). It
// carries NO id — a bond is addressed by its content.
type scheduleBondView struct {
	Amount          brlDecimal `json:"amount"`
	BankCode        string     `json:"bank_code"`
	BankName        string     `json:"bank_name"`
	BeneficiaryName string     `json:"beneficiary_name"`
	Content         string     `json:"content"`
	DueDate         string     `json:"due_date"`
	Overdue         bool       `json:"overdue"`
	PayerName       string     `json:"payer_name"`
}

// scheduleQueryResponseBody wraps the DDA bonds.
type scheduleQueryResponseBody struct {
	Items []scheduleBondView `json:"items"`
}

// scheduleRemoveItem is one entry of the DELETE body. The contract's request body is a
// BARE JSON ARRAY of these — not an object wrapping a list — so the request marshals
// []scheduleRemoveItem directly.
type scheduleRemoveItem struct {
	ID string `json:"id"`
}

// scheduleSubmitRequestBody is the /submit body. BOTH fields are required: the group
// travels in the body here, not in the path.
type scheduleSubmitRequestBody struct {
	GroupID      string `json:"group_id"`
	UploaderName string `json:"uploader_name"`
}

// parseScheduleDate parses the contract's `format: date` (YYYY-MM-DD). An empty or
// unparseable value yields the zero time rather than an error: a PIX payment has no
// due date at all, and a malformed informative date must not fail a read whose money
// fields are sound.
func parseScheduleDate(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(dueDateLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// formatScheduleDate renders a date for the wire, or "" for the zero time so the
// field is omitted and the bank applies its documented default (today).
func formatScheduleDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(dueDateLayout)
}

// toScheduleBonds maps the wire bonds to the port type.
func toScheduleBonds(in scheduleQueryResponseBody) []ports.DDABoleto {
	out := make([]ports.DDABoleto, len(in.Items))
	for i, b := range in.Items {
		out[i] = ports.DDABoleto{
			Content:         b.Content,
			AmountCents:     int64(b.Amount),
			DueDate:         parseScheduleDate(b.DueDate),
			BeneficiaryName: b.BeneficiaryName,
			PayerName:       b.PayerName,
			BankCode:        b.BankCode,
			BankName:        b.BankName,
			Overdue:         b.Overdue,
		}
	}
	return out
}

// toScheduleGroup maps the items of a group onto the port type. The group id comes
// from the caller (the path), falling back to the id echoed on an item — the response
// envelope itself carries none.
func toScheduleGroup(groupID string, in scheduleItemsResponseBody) ports.DDAGroup {
	items := make([]ports.DDAItem, len(in.Items))
	for i, it := range in.Items {
		if groupID == "" {
			groupID = it.GroupID
		}
		items[i] = ports.DDAItem{
			ID:           it.ID,
			Content:      it.Content,
			AmountCents:  int64(it.Amount),
			DueDate:      parseScheduleDate(it.DueDate),
			Status:       it.Status,
			ProductType:  it.ProductType,
			ErrorMessage: it.ErrorMessage,
			Overdue:      it.Overdue,
		}
	}
	return ports.DDAGroup{ID: groupID, Items: items}
}

// ListOpenBoletos reads the bonds open in the tenant's DDA (roteiro AP_02) via GET
// /v1/schedule_payments/query. The bearer token is attached per tenant; the read is
// tenant-scoped through it.
func (p *Provider) ListOpenBoletos(ctx context.Context, tenantID string) ([]ports.DDABoleto, error) {
	const op = "schedule_query_dda"
	endpoint := p.baseURL + schedulePaymentsPath + "/query"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return nil, err
	}
	setPartnerSoftware(httpReq)
	var out scheduleQueryResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return nil, err
	}
	return toScheduleBonds(out), nil
}

// CreatePaymentGroup submits the selected payments for the initial consult (roteiro
// AP_01) via POST /v1/schedule_payments/decode and returns the new group's id. The
// idempotency anchor is forwarded as the PSP Idempotency-Key so a retried submission
// collapses to one group. Complete mediation: an empty anchor, an empty payment list,
// or any payment without a positive amount is refused at the boundary — `amount` is
// required by the contract and a non-positive one is never a valid payment.
//
// The returned group has NO items: the 201 body is the group id alone. Reading them
// back is GetPaymentGroup's job.
func (p *Provider) CreatePaymentGroup(ctx context.Context, tenantID string, req ports.DDAGroupRequest) (ports.DDAGroup, error) {
	const op = "schedule_decode"
	anchor := req.IdempotencyKey
	if anchor == "" || len(req.Payments) == 0 {
		return ports.DDAGroup{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	items := make([]schedulePaymentBody, len(req.Payments))
	for i, pay := range req.Payments {
		if strings.TrimSpace(pay.Content) == "" || pay.AmountCents <= 0 {
			return ports.DDAGroup{}, &Error{Op: op, sentinel: shared.ErrValidation}
		}
		items[i] = schedulePaymentBody{
			Amount:          brlDecimal(pay.AmountCents),
			BankCode:        pay.BankCode,
			BankName:        pay.BankName,
			BeneficiaryName: pay.BeneficiaryName,
			Content:         strings.TrimSpace(pay.Content),
			Description:     pay.Description,
			PayerName:       pay.PayerName,
			TransactionDate: formatScheduleDate(pay.TransactionDate),
		}
	}
	payload, err := json.Marshal(scheduleDecodeRequestBody{Items: items})
	if err != nil {
		return ports.DDAGroup{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}

	endpoint := p.baseURL + schedulePaymentsPath + "/decode"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPost, endpoint, payload, anchor)
	if err != nil {
		return ports.DDAGroup{}, err
	}
	setPartnerSoftware(httpReq)
	var out scheduleDecodeResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.DDAGroup{}, err
	}
	if strings.TrimSpace(out.GroupID) == "" {
		// A 201 without a group id is not a success: without it there is no way to
		// read, trim or submit the group, and returning an empty id would surface as
		// a not-found on the very next call, pointing at the wrong place.
		return ports.DDAGroup{}, &Error{Op: op, sentinel: shared.ErrUnavailable}
	}
	return ports.DDAGroup{ID: out.GroupID}, nil
}

// GetPaymentGroup reconciles the authoritative state of a group's items (roteiro
// AP_03) via GET /v1/schedule_payments/{group_id}/items. A 404 surfaces as
// shared.ErrNotFound; the read is tenant-scoped through the per-tenant bearer.
func (p *Provider) GetPaymentGroup(ctx context.Context, tenantID, groupID string) (ports.DDAGroup, error) {
	const op = "schedule_get_items"
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return ports.DDAGroup{}, &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + schedulePaymentsPath + "/" + url.PathEscape(groupID) + "/items"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.DDAGroup{}, err
	}
	setPartnerSoftware(httpReq)
	var out scheduleItemsResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.DDAGroup{}, err
	}
	return toScheduleGroup(groupID, out), nil
}

// RemovePaymentGroupItems removes a list of items from a group (roteiro AP_04) via a
// DELETE whose body is a BARE ARRAY of {id} objects. A 404 surfaces as
// shared.ErrNotFound.
func (p *Provider) RemovePaymentGroupItems(ctx context.Context, tenantID, groupID string, itemIDs []string) error {
	const op = "schedule_remove_items"
	groupID = strings.TrimSpace(groupID)
	if groupID == "" || len(itemIDs) == 0 {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	body := make([]scheduleRemoveItem, 0, len(itemIDs))
	for _, id := range itemIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			return &Error{Op: op, sentinel: shared.ErrValidation}
		}
		body = append(body, scheduleRemoveItem{ID: id})
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + schedulePaymentsPath + "/" + url.PathEscape(groupID) + "/items"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodDelete, endpoint, payload, "")
	if err != nil {
		return err
	}
	setPartnerSoftware(httpReq)
	return p.doNoContent(httpReq, op)
}

// RemovePaymentGroupItem removes a single item from a group (roteiro AP_05) via a
// DELETE on the item's sub-resource. A 404 surfaces as shared.ErrNotFound.
func (p *Provider) RemovePaymentGroupItem(ctx context.Context, tenantID, groupID, itemID string) error {
	const op = "schedule_remove_item"
	groupID = strings.TrimSpace(groupID)
	itemID = strings.TrimSpace(itemID)
	if groupID == "" || itemID == "" {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + schedulePaymentsPath + "/" + url.PathEscape(groupID) +
		"/items/" + url.PathEscape(itemID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodDelete, endpoint, nil, "")
	if err != nil {
		return err
	}
	setPartnerSoftware(httpReq)
	return p.doNoContent(httpReq, op)
}

// SubmitPaymentGroup submits a group for approval (roteiro AP_06) via POST
// /v1/schedule_payments/submit. The group id travels in the BODY, not the path, and
// uploaderName — the operator shown on the bank's approval screen — is required by
// the contract. idemKey (when present) is forwarded as the PSP Idempotency-Key so a
// retried submit collapses to one effect.
func (p *Provider) SubmitPaymentGroup(ctx context.Context, tenantID, groupID, uploaderName, idemKey string) error {
	const op = "schedule_submit"
	groupID = strings.TrimSpace(groupID)
	uploaderName = strings.TrimSpace(uploaderName)
	if groupID == "" || uploaderName == "" {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	payload, err := json.Marshal(scheduleSubmitRequestBody{GroupID: groupID, UploaderName: uploaderName})
	if err != nil {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + schedulePaymentsPath + "/submit"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPost, endpoint, payload, idemKey)
	if err != nil {
		return err
	}
	setPartnerSoftware(httpReq)
	return p.doNoContent(httpReq, op)
}
