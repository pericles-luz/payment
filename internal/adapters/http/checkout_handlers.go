package http

import (
	"net/http"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/app"
)

// --- Tenant API: unified hosted checkout (roteiro 9.a–9.c) ---

// createCheckoutRequest is the boundary body for POST /v1/checkout. Expiry is given
// as expires_at (RFC3339) or a relative expires_in_seconds; one is required. Unknown
// fields are rejected by decodeJSON (anti mass-assignment).
type createCheckoutRequest struct {
	Currency              string                `json:"currency"`
	Items                 []checkoutItemRequest `json:"items"`
	ExpiresAt             string                `json:"expires_at"`
	ExpiresInSeconds      int64                 `json:"expires_in_seconds"`
	CardType              string                `json:"card_type"`
	RequireAuthentication bool                  `json:"require_authentication"`
}

type checkoutItemRequest struct {
	Description string `json:"description"`
	AmountCents int64  `json:"amount_cents"`
}

// checkoutSessionView is the JSON representation of an opened checkout session
// returned to the tenant. redirect_url is the hosted page the caller sends the payer
// to; card_type/require_authentication echo what was requested (roteiro 9.a–9.c).
type checkoutSessionView struct {
	SessionID             string `json:"session_id"`
	Status                string `json:"status"`
	RedirectURL           string `json:"redirect_url"`
	AmountCents           int64  `json:"amount_cents"`
	CardType              string `json:"card_type"`
	RequireAuthentication bool   `json:"require_authentication"`
}

func (s *Server) handleCreateCheckout(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantFromContext(r.Context())
	idemKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idemKey == "" {
		writeError(w, http.StatusBadRequest, "missing Idempotency-Key header")
		return
	}
	var req createCheckoutRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	in := app.CreateCheckoutSessionInput{
		TenantID:              tenantID,
		Currency:              req.Currency,
		ExpiresInSeconds:      req.ExpiresInSeconds,
		CardType:              req.CardType,
		RequireAuthentication: req.RequireAuthentication,
		IdempotencyKey:        idemKey,
	}
	if raw := strings.TrimSpace(req.ExpiresAt); raw != "" {
		at, ok := parseRFC3339(raw)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid expires_at (RFC3339)")
			return
		}
		in.ExpiresAt = at
	}
	in.Items = make([]app.CheckoutItemInput, len(req.Items))
	for i, it := range req.Items {
		in.Items[i] = app.CheckoutItemInput{Description: it.Description, AmountCents: it.AmountCents}
	}

	p, res, err := s.checkout.CreateSession(r.Context(), in)
	if err != nil {
		writeDomainError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, checkoutSessionView{
		SessionID:             res.SessionID,
		Status:                res.Status,
		RedirectURL:           res.RedirectURL,
		AmountCents:           p.Amount().Cents(),
		CardType:              res.CardType,
		RequireAuthentication: res.RequireAuthentication,
	})
}
