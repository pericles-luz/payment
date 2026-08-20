package http

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- Tenant API: immediate PIX charges (cobrança imediata, roteiro 7.1–7.4) ---

// createPixRequest is the boundary body for POST /v1/pix. Devedor is optional
// (roteiro 7.2). Unknown fields are rejected by decodeJSON (anti mass-assignment).
type createPixRequest struct {
	AmountCents      int64          `json:"amount_cents"`
	Currency         string         `json:"currency"`
	ExpiresInSeconds int64          `json:"expires_in_seconds"`
	Devedor          *pixDevedorReq `json:"devedor"`
	// Bank optionally selects which configured bank handles this charge (multi-bank,
	// SIN-66022); empty keeps header/default routing, and it overrides X-Bank-Id when
	// both are present (ADR-0007).
	Bank string `json:"bank"`
}

type pixDevedorReq struct {
	TaxID string `json:"tax_id"`
	Name  string `json:"name"`
	// Address fields. Optional on an immediate charge (the PSP does not ask for them)
	// and MANDATORY on a due-date charge, where the document is a formal cobrança.
	Street  string `json:"street,omitempty"`
	City    string `json:"city,omitempty"`
	State   string `json:"state,omitempty"`
	ZipCode string `json:"zip_code,omitempty"`
}

// pixChargeView is the JSON representation of an immediate PIX charge returned to
// the tenant. The QR material is what the payer scans; expires_at is omitted when
// the PSP reported no expiry.
type pixChargeView struct {
	TxID                string `json:"txid"`
	Status              string `json:"status"`
	QRCode              string `json:"qr_code"`
	QRCodeLocation      string `json:"qr_code_location"`
	ExpiresAt           string `json:"expires_at,omitempty"`
	AmountCents         int64  `json:"amount_cents"`
	ReceivedAmountCents int64  `json:"received_amount_cents"`
}

// toPixChargeView renders a PixChargeResult. amountCents is the authoritative
// charge amount to surface (the request amount on create, the reconciled expected
// amount on read), so the view is consistent even when the PSP create response does
// not echo valor.
func toPixChargeView(r ports.PixChargeResult, amountCents int64) pixChargeView {
	v := pixChargeView{
		TxID:                r.TxID,
		Status:              r.Status,
		QRCode:              r.QRCodePayload,
		QRCodeLocation:      r.QRCodeLocation,
		AmountCents:         amountCents,
		ReceivedAmountCents: r.ReceivedAmountCents,
	}
	if !r.ExpiresAt.IsZero() {
		v.ExpiresAt = r.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return v
}

func (s *Server) handleCreatePix(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req createPixRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	nr, ok := s.rebindBank(w, r, req.Bank)
	if !ok {
		return
	}
	r = nr
	in := app.CreateImmediateChargeInput{
		TenantID:         tenantID,
		AccountID:        accountFromContext(r.Context()),
		AmountCents:      req.AmountCents,
		Currency:         req.Currency,
		IdempotencyKey:   idemKey,
		ExpiresInSeconds: req.ExpiresInSeconds,
	}
	if req.Devedor != nil {
		in.DebtorTaxID = req.Devedor.TaxID
		in.DebtorName = req.Devedor.Name
	}
	p, qr, err := s.pix.CreateImmediateCharge(r.Context(), in)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toPixChargeView(qr, p.Amount().Cents()))
}

func (s *Server) handleGetPix(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	txID := chi.URLParam(r, "txid")
	qr, err := s.pix.GetImmediateCharge(r.Context(), tenantID, txID)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toPixChargeView(qr, qr.ExpectedAmountCents))
}

// pixListView is the JSON page returned by GET /v1/pix.
type pixListView struct {
	Charges    []pixChargeView `json:"charges"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
	TotalItems int             `json:"total_items"`
	TotalPages int             `json:"total_pages"`
}

func (s *Server) handleListPix(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	q := r.URL.Query()

	start, ok := parseRFC3339(q.Get("start"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing start (RFC3339)")
		return
	}
	end, ok := parseRFC3339(q.Get("end"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing end (RFC3339)")
		return
	}
	page, ok := parseOptionalInt(q.Get("page"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid page")
		return
	}
	pageSize, ok := parseOptionalInt(q.Get("page_size"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid page_size")
		return
	}

	list, err := s.pix.ListImmediateCharges(r.Context(), app.ListImmediateChargesInput{
		TenantID: tenantID,
		Start:    start,
		End:      end,
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}

	views := make([]pixChargeView, 0, len(list.Charges))
	for _, c := range list.Charges {
		views = append(views, toPixChargeView(c, c.ExpectedAmountCents))
	}
	writeJSON(w, http.StatusOK, pixListView{
		Charges:    views,
		Page:       list.Page,
		PageSize:   list.PageSize,
		TotalItems: list.TotalItems,
		TotalPages: list.TotalPages,
	})
}

// parseRFC3339 parses a required RFC3339 timestamp, reporting ok=false when absent
// or malformed.
func parseRFC3339(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// parseOptionalInt parses an optional non-negative integer query parameter. An
// empty value yields (0, true); a malformed or negative value yields ok=false.
func parseOptionalInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
