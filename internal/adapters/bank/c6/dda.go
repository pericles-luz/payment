package c6

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// DDA / agendamento de pagamentos support for the C6 adapter (roteiro grupo 8).
//
// The lifecycle: ListOpenBoletos reads the boletos open in the tenant's DDA;
// CreatePaymentGroup submits selected barcodes for the initial consult and gets back
// the consultando group; GetPaymentGroup reconciles the authoritative group state
// (the source of truth the use-case reads before trimming/submitting); the remove and
// submit operations mutate the group. All DDA endpoints live here so the use-cases
// never speak HTTP/JSON or know the PSP wire shape (Hexagonal).
//
// The JSON shape below is the adapter's clean internal contract (snake_case, explicit
// cents/ids), mirroring the boleto/cobv adapters: it round-trips exactly so Camada A
// (stub mode) is deterministic. Camada B maps it to the real BACEN/C6 DDA wire against
// the homologação endpoint; that translation does not change this port's surface.

// compile-time assertion that Provider satisfies the DDA port.
var _ ports.DDAProvider = (*Provider)(nil)

// ddaBoletoBody is one open boleto in the tenant's DDA (roteiro 8.1).
type ddaBoletoBody struct {
	ID              string    `json:"id"`
	Barcode         string    `json:"barcode"`
	AmountCents     int64     `json:"amount_cents"`
	DueDate         time.Time `json:"due_date"`
	BeneficiaryName string    `json:"beneficiary_name"`
}

// ddaBoletosResponse wraps the 8.1 list response.
type ddaBoletosResponse struct {
	Boletos []ddaBoletoBody `json:"boletos"`
}

// ddaItemBody is one payment line of a group (roteiro 8.3).
type ddaItemBody struct {
	ID          string    `json:"id"`
	Barcode     string    `json:"barcode"`
	AmountCents int64     `json:"amount_cents"`
	DueDate     time.Time `json:"due_date"`
}

// ddaGroupBody is a payment group's representation: id, status and items (roteiro
// 8.2/8.3).
type ddaGroupBody struct {
	ID     string        `json:"id"`
	Status string        `json:"status"`
	Items  []ddaItemBody `json:"items"`
}

// createGroupRequestBody is the JSON sent to submit a consult (roteiro 8.2).
type createGroupRequestBody struct {
	Barcodes []string `json:"barcodes"`
}

// removeItemsRequestBody is the JSON sent to remove a list of items (roteiro 8.4).
type removeItemsRequestBody struct {
	ItemIDs []string `json:"item_ids"`
}

// toDDABoletos maps the wire boletos to the port type.
func toDDABoletos(in ddaBoletosResponse) []ports.DDABoleto {
	out := make([]ports.DDABoleto, len(in.Boletos))
	for i, b := range in.Boletos {
		out[i] = ports.DDABoleto{
			ID:              b.ID,
			Barcode:         b.Barcode,
			AmountCents:     b.AmountCents,
			DueDate:         b.DueDate,
			BeneficiaryName: b.BeneficiaryName,
		}
	}
	return out
}

// toDDAGroup maps a wire group to the port type.
func toDDAGroup(in ddaGroupBody) ports.DDAGroup {
	items := make([]ports.DDAItem, len(in.Items))
	for i, it := range in.Items {
		items[i] = ports.DDAItem{ID: it.ID, Barcode: it.Barcode, AmountCents: it.AmountCents, DueDate: it.DueDate}
	}
	return ports.DDAGroup{ID: in.ID, Status: in.Status, Items: items}
}

// ListOpenBoletos reads the boletos open in the tenant's DDA (roteiro 8.1). The bearer
// token is attached per tenant; the read is tenant-scoped through it.
func (p *Provider) ListOpenBoletos(ctx context.Context, tenantID string) ([]ports.DDABoleto, error) {
	endpoint := p.baseURL + "/v1/dda/boletos"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "dda_list_boletos", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return nil, err
	}
	var out ddaBoletosResponse
	if err := p.do(httpReq, "dda_list_boletos", &out); err != nil {
		return nil, err
	}
	return toDDABoletos(out), nil
}

// CreatePaymentGroup submits selected barcodes for the initial consult (roteiro 8.2)
// and returns the consultando group. The idempotency anchor is forwarded as the PSP
// Idempotency-Key so a retried submission collapses to one group. Complete mediation:
// an empty anchor or an empty barcode list is refused at the boundary.
func (p *Provider) CreatePaymentGroup(ctx context.Context, tenantID string, req ports.DDAGroupRequest) (ports.DDAGroup, error) {
	anchor := req.IdempotencyKey
	if anchor == "" || len(req.Barcodes) == 0 {
		return ports.DDAGroup{}, &Error{Op: "dda_create_group", sentinel: shared.ErrValidation}
	}
	payload, err := json.Marshal(createGroupRequestBody{Barcodes: req.Barcodes})
	if err != nil {
		return ports.DDAGroup{}, &Error{Op: "dda_create_group", sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + "/v1/dda/payment-groups"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "dda_create_group", http.MethodPost, endpoint, payload, anchor)
	if err != nil {
		return ports.DDAGroup{}, err
	}
	var out ddaGroupBody
	if err := p.do(httpReq, "dda_create_group", &out); err != nil {
		return ports.DDAGroup{}, err
	}
	return toDDAGroup(out), nil
}

// GetPaymentGroup reconciles the authoritative state (status + items) of a group
// (roteiro 8.3). A 404 surfaces as shared.ErrNotFound; the read is tenant-scoped
// through the per-tenant bearer.
func (p *Provider) GetPaymentGroup(ctx context.Context, tenantID, groupID string) (ports.DDAGroup, error) {
	endpoint := p.baseURL + "/v1/dda/payment-groups/" + url.PathEscape(groupID) + "/items"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "dda_get_group", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.DDAGroup{}, err
	}
	var out ddaGroupBody
	if err := p.do(httpReq, "dda_get_group", &out); err != nil {
		return ports.DDAGroup{}, err
	}
	return toDDAGroup(out), nil
}

// RemovePaymentGroupItems removes a list of items from a group (roteiro 8.4) via a
// DELETE carrying the id list in the body. A 404 surfaces as shared.ErrNotFound.
func (p *Provider) RemovePaymentGroupItems(ctx context.Context, tenantID, groupID string, itemIDs []string) error {
	if len(itemIDs) == 0 {
		return &Error{Op: "dda_remove_items", sentinel: shared.ErrValidation}
	}
	payload, err := json.Marshal(removeItemsRequestBody{ItemIDs: itemIDs})
	if err != nil {
		return &Error{Op: "dda_remove_items", sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + "/v1/dda/payment-groups/" + url.PathEscape(groupID) + "/items"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "dda_remove_items", http.MethodDelete, endpoint, payload, "")
	if err != nil {
		return err
	}
	return p.doNoContent(httpReq, "dda_remove_items")
}

// RemovePaymentGroupItem removes a single item from a group (roteiro 8.5) via a DELETE
// on the item's sub-resource. A 404 surfaces as shared.ErrNotFound.
func (p *Provider) RemovePaymentGroupItem(ctx context.Context, tenantID, groupID, itemID string) error {
	if strings.TrimSpace(itemID) == "" {
		return &Error{Op: "dda_remove_item", sentinel: shared.ErrValidation}
	}
	endpoint := p.baseURL + "/v1/dda/payment-groups/" + url.PathEscape(groupID) + "/items/" + url.PathEscape(itemID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "dda_remove_item", http.MethodDelete, endpoint, nil, "")
	if err != nil {
		return err
	}
	return p.doNoContent(httpReq, "dda_remove_item")
}

// SubmitPaymentGroup submits a group for approval (roteiro 8.6) via POST on the submit
// sub-resource. idemKey (when present) is forwarded as the PSP Idempotency-Key so a
// retried submit collapses to one effect. A 404 surfaces as shared.ErrNotFound.
func (p *Provider) SubmitPaymentGroup(ctx context.Context, tenantID, groupID, idemKey string) error {
	endpoint := p.baseURL + "/v1/dda/payment-groups/" + url.PathEscape(groupID) + "/submit"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "dda_submit_group", http.MethodPost, endpoint, nil, idemKey)
	if err != nil {
		return err
	}
	return p.doNoContent(httpReq, "dda_submit_group")
}

// doNoContent executes an authenticated request that returns no body on success
// (204 No Content: the DELETE and submit DDA operations). It maps a non-2xx into a
// domain error and, on a 2xx, drains and discards the body. It exists because do()
// decodes a JSON body and would treat an empty 204 body as a malformed response.
func (p *Provider) doNoContent(req *http.Request, op string) error {
	resp, err := p.httpc.Do(req)
	if err != nil {
		return transportError(op)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode/100 != 2 {
		return mapError(op, resp.StatusCode, body)
	}
	return nil
}
