package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
)

// maxBodyBytes caps request bodies to bound memory use (threat H3/W4).
const maxBodyBytes = 1 << 20 // 1 MiB

// decodeJSON strictly decodes a JSON body into v, rejecting unknown fields
// (anti mass-assignment, threat H4) and oversized bodies.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// --- Tenant API: charges ---

type createChargeRequest struct {
	Endpoint    string `json:"endpoint"`
	AmountCents int64  `json:"amount_cents"`
	Currency    string `json:"currency"`
}

type paymentView struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Endpoint string `json:"endpoint"`
	Amount   int64  `json:"amount_cents"`
	Currency string `json:"currency"`
	Status   string `json:"status"`
	TxID     string `json:"tx_id"`
}

func toPaymentView(p *payment.Payment) paymentView {
	return paymentView{
		ID:       p.ID(),
		TenantID: p.TenantID(),
		Endpoint: p.Endpoint(),
		Amount:   p.Amount().Cents(),
		Currency: p.Amount().Currency(),
		Status:   string(p.Status()),
		TxID:     p.TxID(),
	}
}

func (s *Server) handleCreateCharge(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req createChargeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := s.charges.CreateCharge(r.Context(), app.CreateChargeInput{
		TenantID:       tenantID,
		Endpoint:       req.Endpoint,
		AmountCents:    req.AmountCents,
		Currency:       req.Currency,
		IdempotencyKey: idemKey,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toPaymentView(p))
}

func (s *Server) handleGetCharge(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	id := chi.URLParam(r, "id")
	p, err := s.charges.GetPayment(r.Context(), tenantID, id)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toPaymentView(p))
}

// --- Admin plane ---

type createTenantRequest struct {
	Name string `json:"name"`
}

type tenantView struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := s.admin.CreateTenant(r.Context(), req.Name)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, tenantView{ID: t.ID(), Name: t.Name(), Active: t.Active()})
}

type setPriceRequest struct {
	Endpoint   string `json:"endpoint"`
	PriceCents int64  `json:"price_cents"`
}

type priceView struct {
	TenantID   string `json:"tenant_id"`
	Endpoint   string `json:"endpoint"`
	PriceCents int64  `json:"price_cents"`
}

func (s *Server) handleSetPrice(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	var req setPriceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	p, err := s.admin.SetEndpointPrice(r.Context(), tenantID, req.Endpoint, req.PriceCents)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, priceView{TenantID: p.TenantID(), Endpoint: p.Endpoint(), PriceCents: p.PriceCents()})
}

// setBankCredentialRequest carries a tenant's PSP credential. The secret is
// write-only: it is accepted here and forwarded to the secret store, never read
// back, logged or echoed in any response (threat C1/C4).
type setBankCredentialRequest struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"secret"`
}

// bankCredentialView confirms a credential write WITHOUT the secret.
type bankCredentialView struct {
	TenantID string `json:"tenant_id"`
	ClientID string `json:"client_id"`
	Status   string `json:"status"`
}

func (s *Server) handleSetBankCredential(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	var req setBankCredentialRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.admin.SetBankCredential(r.Context(), tenantID, req.ClientID, req.Secret); err != nil {
		writeDomainError(w, err)
		return
	}
	// Echo only non-secret fields so the secret never leaves the secret store.
	writeJSON(w, http.StatusOK, bankCredentialView{TenantID: tenantID, ClientID: req.ClientID, Status: "ok"})
}

// --- Bank webhook ---

type webhookRequest struct {
	TenantID string `json:"tenant_id"`
	TxID     string `json:"tx_id"`
	EventKey string `json:"event_key"`
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	// Failure-closed authentication of the inbound webhook (threat W1).
	if !s.webhookAuth.AuthenticateWebhook(r.Header.Get("X-Webhook-Secret")) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req webhookRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.webhooks.HandlePaymentEvent(r.Context(), app.PaymentEvent{
		TenantID: req.TenantID,
		TxID:     req.TxID,
		EventKey: req.EventKey,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	// 202: accepted; reconciliation/settlement already attempted synchronously.
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}
