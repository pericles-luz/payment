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

// --- Tenant API: DDA / agendamento de pagamentos (roteiro grupo 8) ---
//
// Every handler derives the tenant from the authenticated context (tenantFromContext),
// never from the body or path: a payment group owned by another tenant is 404 (the
// use-case maps cross-tenant access to shared.ErrNotFound, no existence oracle). Writes
// (8.2 create, 8.6 submit) require an Idempotency-Key header so a retry collapses to one
// effect. Bodies are decoded with DisallowUnknownFields (anti mass-assignment).

// ddaBoletoView is the JSON representation of one boleto open in the tenant's DDA
// (roteiro 8.1).
type ddaBoletoView struct {
	ID              string `json:"id"`
	Barcode         string `json:"barcode"`
	AmountCents     int64  `json:"amount_cents"`
	DueDate         string `json:"due_date"`
	BeneficiaryName string `json:"beneficiary_name"`
}

// ddaItemView is the JSON representation of one payment line of a group (roteiro 8.3).
type ddaItemView struct {
	ID          string `json:"id"`
	Barcode     string `json:"barcode"`
	AmountCents int64  `json:"amount_cents"`
	DueDate     string `json:"due_date"`
}

// ddaGroupView is the JSON representation of a created payment group (roteiro 8.2). The
// txid is the group identifier the caller addresses in 8.3–8.6.
type ddaGroupView struct {
	TxID   string        `json:"txid"`
	Status string        `json:"status"`
	Items  []ddaItemView `json:"items"`
}

// createDDAGroupRequest is the boundary body for POST /v1/dda/payment-groups: the
// boletos (by barcode / linha digitável) selected into the group for the initial
// consult. Unknown fields are rejected by decodeJSON.
type createDDAGroupRequest struct {
	Barcodes []string `json:"barcodes"`
}

// removeDDAItemsRequest is the boundary body for DELETE /v1/dda/payment-groups/{id}/items
// (roteiro 8.4): the list of item ids to remove from the group.
type removeDDAItemsRequest struct {
	ItemIDs []string `json:"item_ids"`
}

// writeDDAError maps a DDA error to a safe HTTP status. An illegal aggregate transition
// (trimming or submitting a frozen/approved group) is a 409 Conflict — the request is
// well-formed but the resource is not in a state that permits it. Everything else falls
// through to the shared mapping (validation→400, not-found→404, etc.).
func writeDDAError(w http.ResponseWriter, err error) {
	if errors.Is(err, shared.ErrInvalidTransition) {
		writeError(w, http.StatusConflict, "conflict")
		return
	}
	writeDomainError(w, err)
}

// handleListDDABoletos returns the boletos open in the authenticated tenant's DDA
// (roteiro 8.1, GET /v1/dda/boletos → 200).
func (s *Server) handleListDDABoletos(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	boletos, err := s.dda.ListOpenBoletos(r.Context(), tenantID)
	if err != nil {
		writeDDAError(w, err)
		return
	}
	out := make([]ddaBoletoView, len(boletos))
	for i, b := range boletos {
		out[i] = toDDABoletoView(b)
	}
	writeJSON(w, http.StatusOK, map[string]any{"boletos": out})
}

// handleCreateDDAGroup submits the selected boletos for the initial consult (roteiro
// 8.2, POST /v1/dda/payment-groups → 201 + txid). The Idempotency-Key header is
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
	group, err := s.dda.CreatePaymentGroup(r.Context(), app.CreateGroupInput{
		TenantID:       tenantID,
		Barcodes:       req.Barcodes,
		IdempotencyKey: idemKey,
	})
	if err != nil {
		writeDDAError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toDDAGroupView(group))
}

// handleGetDDAGroupItems reconciles a group's items (roteiro 8.3, GET
// /v1/dda/payment-groups/{id}/items → 200). A group owned by another tenant — like an
// unknown id — is 404.
func (s *Server) handleGetDDAGroupItems(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	items, err := s.dda.GetPaymentGroupItems(r.Context(), tenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeDDAError(w, err)
		return
	}
	out := make([]ddaItemView, len(items))
	for i, it := range items {
		out[i] = toDDAItemView(it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// handleRemoveDDAGroupItems removes a list of items from a group (roteiro 8.4, DELETE
// /v1/dda/payment-groups/{id}/items → 204). The id list is the request body. An approved
// group is frozen → 409.
func (s *Server) handleRemoveDDAGroupItems(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	var req removeDDAItemsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.dda.RemovePaymentGroupItems(r.Context(), tenantID, chi.URLParam(r, "id"), req.ItemIDs); err != nil {
		writeDDAError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveDDAGroupItem removes a single item from a group (roteiro 8.5, DELETE
// /v1/dda/payment-groups/{id}/items/{itemID} → 204). An approved group is frozen → 409.
func (s *Server) handleRemoveDDAGroupItem(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	if err := s.dda.RemovePaymentGroupItem(r.Context(), tenantID, chi.URLParam(r, "id"), chi.URLParam(r, "itemID")); err != nil {
		writeDDAError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSubmitDDAGroup submits a consulting group for approval (roteiro 8.6, POST
// /v1/dda/payment-groups/{id}/submit → 204). The Idempotency-Key header is mandatory;
// submitting an already-approved group is an idempotent no-op (204).
func (s *Server) handleSubmitDDAGroup(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	if err := s.dda.SubmitPaymentGroup(r.Context(), tenantID, chi.URLParam(r, "id"), idemKey); err != nil {
		writeDDAError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// toDDABoletoView maps a port boleto onto the tenant-facing view (due date as RFC3339).
func toDDABoletoView(b ports.DDABoleto) ddaBoletoView {
	return ddaBoletoView{
		ID:              b.ID,
		Barcode:         b.Barcode,
		AmountCents:     b.AmountCents,
		DueDate:         b.DueDate.UTC().Format(time.RFC3339),
		BeneficiaryName: b.BeneficiaryName,
	}
}

// toDDAItemView maps a port item onto the tenant-facing view.
func toDDAItemView(it ports.DDAItem) ddaItemView {
	return ddaItemView{
		ID:          it.ID,
		Barcode:     it.Barcode,
		AmountCents: it.AmountCents,
		DueDate:     it.DueDate.UTC().Format(time.RFC3339),
	}
}

// toDDAGroupView maps a created group onto the tenant-facing view (the group id is the
// txid the caller addresses in subsequent operations).
func toDDAGroupView(g ports.DDAGroup) ddaGroupView {
	items := make([]ddaItemView, len(g.Items))
	for i, it := range g.Items {
		items[i] = toDDAItemView(it)
	}
	return ddaGroupView{TxID: g.ID, Status: g.Status, Items: items}
}
