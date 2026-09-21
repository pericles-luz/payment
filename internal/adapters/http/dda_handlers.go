package http

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- Tenant API: Agendamento de Pagamentos (roteiro grupo AP) ---
//
// Every handler derives the tenant from the authenticated context (tenantFromContext),
// never from the body or path: a payment group owned by another tenant is 404 (the
// use-case maps cross-tenant access to shared.ErrNotFound, no existence oracle). Writes
// (AP_01 create, AP_06 submit) require an Idempotency-Key header so a retry collapses to one
// effect. Bodies are decoded with DisallowUnknownFields (anti mass-assignment).

// ddaBoletoView is the JSON representation of one bond open in the tenant's DDA
// (roteiro AP_02). It has no id because the bank's `bonds` has none: a bond is
// addressed by its content, which is what the create takes.
type ddaBoletoView struct {
	Content         string `json:"content"`
	AmountCents     int64  `json:"amount_cents"`
	DueDate         string `json:"due_date"`
	BeneficiaryName string `json:"beneficiary_name"`
	PayerName       string `json:"payer_name"`
	BankCode        string `json:"bank_code"`
	BankName        string `json:"bank_name"`
	Overdue         bool   `json:"overdue"`
}

// ddaItemView is the JSON representation of one payment line of a group (roteiro
// AP_03). Status and ProductType are the bank's own vocabulary, passed through
// verbatim (READ_DATA/SCHEDULED/…; BOLETO/PIX) rather than translated: a caller
// deciding what to do next needs the bank's answer, not our paraphrase of it.
type ddaItemView struct {
	ID           string `json:"id"`
	Content      string `json:"content"`
	AmountCents  int64  `json:"amount_cents"`
	DueDate      string `json:"due_date"`
	Status       string `json:"status"`
	ProductType  string `json:"product_type"`
	ErrorMessage string `json:"error_message"`
	Overdue      bool   `json:"overdue"`
}

// ddaGroupView is the JSON representation of a created payment group (roteiro AP_01).
// The txid is the group identifier the caller addresses in AP_03–AP_06. It carries no
// items and no status because the bank's create answers with the id alone — read the
// group back to see them.
type ddaGroupView struct {
	TxID string `json:"txid"`
}

// createDDAPaymentRequest is one payment submitted into the group. Only content and
// amount_cents are required; the rest is informative and shows on the bank's approval
// screen. transaction_date is the execution date (YYYY-MM-DD); empty means today.
type createDDAPaymentRequest struct {
	Content         string `json:"content"`
	AmountCents     int64  `json:"amount_cents"`
	Description     string `json:"description"`
	BeneficiaryName string `json:"beneficiary_name"`
	PayerName       string `json:"payer_name"`
	BankCode        string `json:"bank_code"`
	BankName        string `json:"bank_name"`
	TransactionDate string `json:"transaction_date"`
}

// createDDAGroupRequest is the boundary body for POST /v1/dda/payment-groups: the
// payments selected into the group for the initial consult. Unknown fields are
// rejected by decodeJSON.
type createDDAGroupRequest struct {
	Payments []createDDAPaymentRequest `json:"payments"`
	// Bank optionally selects which configured bank schedules this group
	// (multi-bank, SIN-66022); empty keeps header/default routing, overrides
	// X-Bank-Id (ADR-0007).
	Bank string `json:"bank"`
}

// removeDDAItemsRequest is the boundary body for DELETE /v1/dda/payment-groups/{id}/items
// (roteiro AP_04): the list of item ids to remove from the group.
type removeDDAItemsRequest struct {
	ItemIDs []string `json:"item_ids"`
}

// submitDDAGroupRequest is the boundary body for POST
// /v1/dda/payment-groups/{id}/submit (roteiro AP_06). uploader_name is the operator
// the bank shows on its approval screen and the contract requires it.
type submitDDAGroupRequest struct {
	UploaderName string `json:"uploader_name"`
}

// writeDDAError maps a DDA error to a safe HTTP status. An illegal aggregate transition
// (trimming or submitting a frozen/approved group) is a 409 Conflict — the request is
// well-formed but the resource is not in a state that permits it. Everything else falls
// through to the shared mapping (validation→400, not-found→404, etc.).
func writeDDAError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, shared.ErrInvalidTransition) {
		writeError(w, http.StatusConflict, "conflict")
		return
	}
	writeDomainError(w, r, err)
}

// handleListDDABoletos returns the bonds open in the authenticated tenant's DDA
// (roteiro AP_02, GET /v1/dda/boletos → 200).
func (s *Server) handleListDDABoletos(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	boletos, err := s.dda.ListOpenBoletos(r.Context(), tenantID)
	if err != nil {
		writeDDAError(w, r, err)
		return
	}
	out := make([]ddaBoletoView, len(boletos))
	for i, b := range boletos {
		out[i] = toDDABoletoView(b)
	}
	writeJSON(w, http.StatusOK, map[string]any{"boletos": out})
}

// handleCreateDDAGroup submits the selected payments for the initial consult (roteiro
// AP_01, POST /v1/dda/payment-groups → 201 + txid). The Idempotency-Key header is
// mandatory; a retry with the same key resolves to the same group.
func (s *Server) handleCreateDDAGroup(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req createDDAGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	nr, ok := s.rebindBank(w, r, req.Bank)
	if !ok {
		return
	}
	r = nr
	payments := make([]ports.DDAPayment, len(req.Payments))
	for i, pay := range req.Payments {
		when, ok := parseDDADate(w, pay.TransactionDate)
		if !ok {
			return
		}
		payments[i] = ports.DDAPayment{
			Content:         pay.Content,
			AmountCents:     pay.AmountCents,
			Description:     pay.Description,
			BeneficiaryName: pay.BeneficiaryName,
			PayerName:       pay.PayerName,
			BankCode:        pay.BankCode,
			BankName:        pay.BankName,
			TransactionDate: when,
		}
	}
	group, err := s.dda.CreatePaymentGroup(r.Context(), app.CreateGroupInput{
		TenantID:       tenantID,
		Payments:       payments,
		IdempotencyKey: idemKey,
	})
	if err != nil {
		writeDDAError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, ddaGroupView{TxID: group.ID})
}

// parseDDADate parses an optional YYYY-MM-DD execution date from the request body,
// writing a 400 and returning false when it is present but malformed. An empty value
// is the zero time, which the adapter omits so the bank applies its documented
// default (today).
func parseDDADate(w http.ResponseWriter, raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, true
	}
	t, err := time.Parse("2006-01-02", raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "transaction_date must be YYYY-MM-DD")
		return time.Time{}, false
	}
	return t, true
}

// handleGetDDAGroupItems reconciles a group's items (roteiro 8.3, GET
// /v1/dda/payment-groups/{id}/items → 200). A group owned by another tenant — like an
// unknown id — is 404.
func (s *Server) handleGetDDAGroupItems(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	items, err := s.dda.GetPaymentGroupItems(r.Context(), tenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeDDAError(w, r, err)
		return
	}
	out := make([]ddaItemView, len(items))
	for i, it := range items {
		out[i] = toDDAItemView(it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// handleRemoveDDAGroupItems removes a list of items from a group (roteiro AP_04,
// DELETE /v1/dda/payment-groups/{id}/items → 204). The id list is the request body. A
// submitted group is frozen → 409.
func (s *Server) handleRemoveDDAGroupItems(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	var req removeDDAItemsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.dda.RemovePaymentGroupItems(r.Context(), tenantID, chi.URLParam(r, "id"), req.ItemIDs); err != nil {
		writeDDAError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveDDAGroupItem removes a single item from a group (roteiro AP_05, DELETE
// /v1/dda/payment-groups/{id}/items/{itemID} → 204). A submitted group is frozen → 409.
func (s *Server) handleRemoveDDAGroupItem(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	if err := s.dda.RemovePaymentGroupItem(r.Context(), tenantID, chi.URLParam(r, "id"), chi.URLParam(r, "itemID")); err != nil {
		writeDDAError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSubmitDDAGroup submits a group for approval (roteiro AP_06, POST
// /v1/dda/payment-groups/{id}/submit → 204). The Idempotency-Key header is mandatory
// and uploader_name is required in the body; submitting an already-submitted group is
// an idempotent no-op (204).
func (s *Server) handleSubmitDDAGroup(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req submitDDAGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.dda.SubmitPaymentGroup(r.Context(), tenantID, chi.URLParam(r, "id"), req.UploaderName, idemKey); err != nil {
		writeDDAError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// toDDABoletoView maps a port bond onto the tenant-facing view.
func toDDABoletoView(b ports.DDABoleto) ddaBoletoView {
	return ddaBoletoView{
		Content:         b.Content,
		AmountCents:     b.AmountCents,
		DueDate:         formatDDADate(b.DueDate),
		BeneficiaryName: b.BeneficiaryName,
		PayerName:       b.PayerName,
		BankCode:        b.BankCode,
		BankName:        b.BankName,
		Overdue:         b.Overdue,
	}
}

// toDDAItemView maps a port item onto the tenant-facing view.
func toDDAItemView(it ports.DDAItem) ddaItemView {
	return ddaItemView{
		ID:           it.ID,
		Content:      it.Content,
		AmountCents:  it.AmountCents,
		DueDate:      formatDDADate(it.DueDate),
		Status:       it.Status,
		ProductType:  it.ProductType,
		ErrorMessage: it.ErrorMessage,
		Overdue:      it.Overdue,
	}
}

// formatDDADate renders a date as RFC3339, or EMPTY for the zero time. A PIX payment
// has no due date at all, and rendering that as "0001-01-01T00:00:00Z" would hand the
// caller a date that looks real.
func formatDDADate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
