package http

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- Tenant API: PIX cobrança com vencimento (cobv, roteiro 7.5–7.7) ---

// cobvRequest is the boundary body shared by POST /v1/pix/cobv and PUT
// /v1/pix/cobv/{txid}. due_date is RFC3339; the devedor and creditor_key are
// required. Unknown fields are rejected by decodeJSON (anti mass-assignment).
type cobvRequest struct {
	AmountCents        int64          `json:"amount_cents"`
	Currency           string         `json:"currency"`
	DueDate            string         `json:"due_date"`
	ValidityDays       int            `json:"validity_days"`
	FineBps            int64          `json:"fine_bps"`
	MonthlyInterestBps int64          `json:"monthly_interest_bps"`
	DiscountBps        int64          `json:"discount_bps"`
	DiscountFixedCents int64          `json:"discount_fixed_cents"`
	Devedor            *pixDevedorReq `json:"devedor"`
	CreditorKey        string         `json:"creditor_key"`
}

// cobvView is the JSON representation of a cobv charge returned to the tenant. The
// QR material is what the payer scans; the registered parameters are echoed for
// reconciliation/homologação evidence.
type cobvView struct {
	TxID                string `json:"txid"`
	Status              string `json:"status"`
	QRCode              string `json:"qr_code"`
	QRCodeLocation      string `json:"qr_code_location"`
	DueDate             string `json:"due_date,omitempty"`
	ValidityDays        int    `json:"validity_days"`
	FineBps             int64  `json:"fine_bps"`
	MonthlyInterestBps  int64  `json:"monthly_interest_bps"`
	DiscountBps         int64  `json:"discount_bps,omitempty"`
	DiscountFixedCents  int64  `json:"discount_fixed_cents,omitempty"`
	AmountCents         int64  `json:"amount_cents"`
	ReceivedAmountCents int64  `json:"received_amount_cents"`
}

// toCobvView renders a PixDueChargeResult. amountCents is the authoritative charge
// amount to surface (the request amount on create, the reconciled expected amount on
// read).
func toCobvView(r ports.PixDueChargeResult, amountCents int64) cobvView {
	v := cobvView{
		TxID:                r.TxID,
		Status:              r.Status,
		QRCode:              r.QRCodePayload,
		QRCodeLocation:      r.QRCodeLocation,
		ValidityDays:        r.ValidityDays,
		FineBps:             r.FineBps,
		MonthlyInterestBps:  r.MonthlyInterestBps,
		DiscountBps:         r.DiscountBps,
		DiscountFixedCents:  r.DiscountFixedCents,
		AmountCents:         amountCents,
		ReceivedAmountCents: r.ReceivedAmountCents,
	}
	if !r.DueDate.IsZero() {
		v.DueDate = r.DueDate.UTC().Format(time.RFC3339)
	}
	return v
}

// toDueChargeInput maps the validated boundary body to the use-case input. The due
// date has already been parsed.
func toDueChargeInput(tenantID, idemKey string, req cobvRequest, due time.Time) app.DueChargeInput {
	in := app.DueChargeInput{
		TenantID:           tenantID,
		AmountCents:        req.AmountCents,
		Currency:           req.Currency,
		DueDate:            due,
		ValidityDays:       req.ValidityDays,
		FineBps:            req.FineBps,
		MonthlyInterestBps: req.MonthlyInterestBps,
		DiscountBps:        req.DiscountBps,
		DiscountFixedCents: req.DiscountFixedCents,
		CreditorKey:        req.CreditorKey,
		IdempotencyKey:     idemKey,
	}
	if req.Devedor != nil {
		in.DebtorTaxID = req.Devedor.TaxID
		in.DebtorName = req.Devedor.Name
	}
	return in
}

func (s *Server) handleCreatePixCobV(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req cobvRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	due, ok := parseRFC3339(req.DueDate)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing due_date (RFC3339)")
		return
	}

	p, res, err := s.pixCobV.CreateDueCharge(r.Context(), toDueChargeInput(tenantID, idemKey, req, due))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCobvView(res, p.Amount().Cents()))
}

func (s *Server) handleGetPixCobV(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	txID := chi.URLParam(r, "txid")
	res, err := s.pixCobV.GetDueCharge(r.Context(), tenantID, txID)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toCobvView(res, res.ExpectedAmountCents))
}

func (s *Server) handleUpdatePixCobV(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	txID := chi.URLParam(r, "txid")
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req cobvRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	due, ok := parseRFC3339(req.DueDate)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing due_date (RFC3339)")
		return
	}

	res, err := s.pixCobV.UpdateDueCharge(r.Context(), tenantID, txID, toDueChargeInput(tenantID, idemKey, req, due))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toCobvView(res, res.ExpectedAmountCents))
}
