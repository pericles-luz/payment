package http

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- Tenant API: BolePix boletos (roteiro grupos 1–6) ---

// boletoDiscountReq is one early-payment discount tier in the request body (group 3).
// Exactly one of bps/fixed_cents must be set.
type boletoDiscountReq struct {
	DaysBeforeDue int   `json:"days_before_due"`
	Bps           int64 `json:"bps"`
	FixedCents    int64 `json:"fixed_cents"`
}

// boletoAddressReq is the payer address in the request body (ADR-0005). number is an
// integer mirroring the C6 contract.
type boletoAddressReq struct {
	Street  string `json:"street"`
	Number  int    `json:"number"`
	City    string `json:"city"`
	State   string `json:"state"`
	ZipCode string `json:"zip_code"`
}

// boletoPayerReq is the nested payer block in the request body (ADR-0005). It is
// optional at the boundary; the C6 adapter is the one that requires the full payer.
type boletoPayerReq struct {
	Name    string           `json:"name"`
	TaxID   string           `json:"tax_id"`
	Address boletoAddressReq `json:"address"`
}

// createBoletoRequest is the boundary body for POST /v1/boletos. due_date is RFC3339.
// fine_bps/monthly_interest_bps express the late-payment rates (groups 1–2); discounts
// the early-payment schedule (group 3). payer is the nested sacado/pagador block
// (ADR-0005), optional at the boundary. Unknown fields (including nested ones) are
// rejected by decodeJSON (anti mass-assignment).
type createBoletoRequest struct {
	AmountCents        int64               `json:"amount_cents"`
	Currency           string              `json:"currency"`
	DueDate            string              `json:"due_date"`
	FineBps            int64               `json:"fine_bps"`
	FineFixedCents     int64               `json:"fine_fixed_cents"`
	MonthlyInterestBps int64               `json:"monthly_interest_bps"`
	Discounts          []boletoDiscountReq `json:"discounts"`
	Payer              boletoPayerReq      `json:"payer"`
}

// toPayerInput maps the nested payer request block to the use-case input.
func toPayerInput(p boletoPayerReq) app.BoletoPayerInput {
	return app.BoletoPayerInput{
		Name:  p.Name,
		TaxID: p.TaxID,
		Address: app.BoletoAddressInput{
			Street:  p.Address.Street,
			Number:  p.Address.Number,
			City:    p.Address.City,
			State:   p.Address.State,
			ZipCode: p.Address.ZipCode,
		},
	}
}

// updateBoletoRequest is the boundary body for PUT /v1/boletos/{id} (alteração, grupo
// 5): due date (5.a), validity (5.b), amount/fine/interest (5.c). due_date/valid_until
// are RFC3339. Unknown fields are rejected by decodeJSON (anti mass-assignment).
type updateBoletoRequest struct {
	AmountCents        int64               `json:"amount_cents"`
	Currency           string              `json:"currency"`
	DueDate            string              `json:"due_date"`
	ValidUntil         string              `json:"valid_until"`
	FineBps            int64               `json:"fine_bps"`
	FineFixedCents     int64               `json:"fine_fixed_cents"`
	MonthlyInterestBps int64               `json:"monthly_interest_bps"`
	Discounts          []boletoDiscountReq `json:"discounts"`
}

// toDiscountInputs maps the boundary discount tiers to the use-case inputs.
func toDiscountInputs(in []boletoDiscountReq) []app.DiscountTierInput {
	out := make([]app.DiscountTierInput, len(in))
	for i, d := range in {
		out[i] = app.DiscountTierInput{DaysBeforeDue: d.DaysBeforeDue, Bps: d.Bps, FixedCents: d.FixedCents}
	}
	return out
}

// boletoDiscountView mirrors a registered discount tier in the response.
type boletoDiscountView struct {
	DaysBeforeDue int   `json:"days_before_due"`
	Bps           int64 `json:"bps,omitempty"`
	FixedCents    int64 `json:"fixed_cents,omitempty"`
}

// boletoView is the JSON representation of a registered boleto returned to the tenant.
// qr_code is the BolePix EMV copy-and-paste payload and barcode the linha digitável;
// the registered parameters are echoed for reconciliation/homologação evidence.
type boletoView struct {
	BoletoID           string               `json:"boleto_id"`
	TxID               string               `json:"txid"`
	Status             string               `json:"status"`
	QRCode             string               `json:"qr_code"`
	Barcode            string               `json:"barcode"`
	AmountCents        int64                `json:"amount_cents"`
	DueDate            string               `json:"due_date,omitempty"`
	ValidUntil         string               `json:"valid_until,omitempty"`
	FineBps            int64                `json:"fine_bps"`
	FineFixedCents     int64                `json:"fine_fixed_cents,omitempty"`
	MonthlyInterestBps int64                `json:"monthly_interest_bps"`
	Discounts          []boletoDiscountView `json:"discounts,omitempty"`
}

// toBoletoView renders a BoletoResult. amountCents is the authoritative principal to
// surface (the request principal on register, the reconciled amount on read).
func toBoletoView(r ports.BoletoResult, amountCents int64) boletoView {
	v := boletoView{
		BoletoID:           r.BoletoID,
		TxID:               r.TxID,
		Status:             r.Status,
		QRCode:             r.QRCode,
		Barcode:            r.Barcode,
		AmountCents:        amountCents,
		FineBps:            r.FineBps,
		FineFixedCents:     r.FineFixedCents,
		MonthlyInterestBps: r.MonthlyInterestBps,
	}
	if !r.DueDate.IsZero() {
		v.DueDate = r.DueDate.UTC().Format(time.RFC3339)
	}
	if !r.ValidUntil.IsZero() {
		v.ValidUntil = r.ValidUntil.UTC().Format(time.RFC3339)
	}
	if len(r.Discounts) > 0 {
		v.Discounts = make([]boletoDiscountView, len(r.Discounts))
		for i, d := range r.Discounts {
			v.Discounts[i] = boletoDiscountView{DaysBeforeDue: d.DaysBeforeDue, Bps: d.Bps, FixedCents: d.FixedCents}
		}
	}
	return v
}

func (s *Server) handleCreateBoleto(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req createBoletoRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	due, ok := parseRFC3339(req.DueDate)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing due_date (RFC3339)")
		return
	}

	in := app.RegisterBoletoInput{
		TenantID:           tenantID,
		AmountCents:        req.AmountCents,
		Currency:           req.Currency,
		DueDate:            due,
		FineBps:            req.FineBps,
		FineFixedCents:     req.FineFixedCents,
		MonthlyInterestBps: req.MonthlyInterestBps,
		Payer:              toPayerInput(req.Payer),
		IdempotencyKey:     idemKey,
		Discounts:          toDiscountInputs(req.Discounts),
	}

	p, res, err := s.boleto.RegisterBoleto(r.Context(), in)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toBoletoView(res, p.Amount().Cents()))
}

func (s *Server) handleGetBoleto(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	id := chi.URLParam(r, "id")
	res, err := s.boleto.GetBoleto(r.Context(), tenantID, id)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toBoletoView(res, res.AmountCents))
}

// handleDeleteBoleto performs the baixa/cancelamento of a boleto (roteiro grupo 4)
// and returns 204 No Content on success.
func (s *Server) handleDeleteBoleto(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	id := chi.URLParam(r, "id")
	if err := s.boleto.CancelBoleto(r.Context(), tenantID, id); err != nil {
		writeDomainError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleUpdateBoleto amends a boleto's parameters (roteiro grupo 5) and returns the
// updated representation. The Idempotency-Key header is mandatory (write).
func (s *Server) handleUpdateBoleto(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	id := chi.URLParam(r, "id")
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req updateBoletoRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	due, ok := parseRFC3339(req.DueDate)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid or missing due_date (RFC3339)")
		return
	}

	in := app.UpdateBoletoInput{
		TenantID:           tenantID,
		AmountCents:        req.AmountCents,
		Currency:           req.Currency,
		DueDate:            due,
		FineBps:            req.FineBps,
		FineFixedCents:     req.FineFixedCents,
		MonthlyInterestBps: req.MonthlyInterestBps,
		IdempotencyKey:     idemKey,
		Discounts:          toDiscountInputs(req.Discounts),
	}
	if raw := strings.TrimSpace(req.ValidUntil); raw != "" {
		vu, ok := parseRFC3339(raw)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid valid_until (RFC3339)")
			return
		}
		in.ValidUntil = vu
	}

	res, err := s.boleto.UpdateBoleto(r.Context(), tenantID, id, in)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toBoletoView(res, res.AmountCents))
}
