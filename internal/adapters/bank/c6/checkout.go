package c6

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// compile-time assertion that Provider satisfies the checkout port.
var _ ports.CheckoutProvider = (*Provider)(nil)

// checkoutItemBody is one line of a checkout request as sent to C6.
type checkoutItemBody struct {
	Description string `json:"description"`
	AmountCents int64  `json:"amount_cents"`
}

// checkoutRequestBody is the JSON sent to C6 to open a hosted checkout session.
type checkoutRequestBody struct {
	SessionID string             `json:"session_id"`
	Currency  string             `json:"currency"`
	Items     []checkoutItemBody `json:"items"`
	ExpiresAt time.Time          `json:"expires_at"`
}

// checkoutResponseBody is the subset of C6's checkout-session representation we
// consume: the status and the hosted redirect URL.
type checkoutResponseBody struct {
	SessionID   string `json:"session_id"`
	Status      string `json:"status"`
	RedirectURL string `json:"redirect_url"`
	AmountCents int64  `json:"amount_cents"`
}

// CreateCheckoutSession opens a unified hosted checkout session at C6 and returns
// the redirect URL the caller sends the payer to. The caller's IdempotencyKey
// (falling back to the SessionID) is forwarded so the PSP collapses retried
// openings into one session. The OAuth2 bearer token is attached per tenant.
func (p *Provider) CreateCheckoutSession(ctx context.Context, tenantID string, req ports.CheckoutRequest) (ports.CheckoutResult, error) {
	items := make([]checkoutItemBody, len(req.Items))
	for i, it := range req.Items {
		items[i] = checkoutItemBody{Description: it.Description, AmountCents: it.AmountCents}
	}
	payload, err := json.Marshal(checkoutRequestBody{
		SessionID: req.SessionID,
		Currency:  req.Currency,
		Items:     items,
		ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		return ports.CheckoutResult{}, &Error{Op: "create_checkout", sentinel: shared.ErrValidation}
	}

	idem := req.IdempotencyKey
	if idem == "" {
		idem = req.SessionID
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_checkout", http.MethodPost, p.baseURL+"/checkout/sessions", payload, idem)
	if err != nil {
		return ports.CheckoutResult{}, err
	}

	var out checkoutResponseBody
	if err := p.do(httpReq, "create_checkout", &out); err != nil {
		return ports.CheckoutResult{}, err
	}
	// Defense-in-depth (open-redirect): the caller redirects the payer to this
	// URL. TLS protects the response in transit, but a tampered or compromised
	// PSP could return a well-formed non-https / relative / opaque target and send
	// the payer to phishing. Refuse anything that is not an absolute https URL
	// rather than forward it. (A host allowlist of the C6 checkout domain would be
	// stronger; it is a documented residual pending per-environment config.)
	if err := validateRedirectURL(out.RedirectURL); err != nil {
		return ports.CheckoutResult{}, err
	}
	return ports.CheckoutResult{
		SessionID:   out.SessionID,
		Status:      out.Status,
		RedirectURL: out.RedirectURL,
		AmountCents: out.AmountCents,
	}, nil
}

// validateRedirectURL rejects a checkout redirect target that is not an absolute
// https URL (empty/relative/opaque/non-https). It returns an *Error wrapping
// shared.ErrUnavailable — the upstream returned a 2xx the adapter cannot safely
// use — and never embeds the raw value, so a malicious URL cannot leak through an
// error or log.
func validateRedirectURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return &Error{Op: "create_checkout", detail: "untrusted redirect url", sentinel: shared.ErrUnavailable}
	}
	return nil
}
