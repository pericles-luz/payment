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

// compile-time assertion that Provider satisfies the checkout port.
var _ ports.CheckoutProvider = (*Provider)(nil)

// checkoutPath is the real C6 checkout collection (OpenAPI "API de Checkout" v1.1.4,
// POST /v1/checkouts/). The trailing slash is appended at call sites to match the
// spec path "/". GET /{id} reconciles and PUT /{id}/cancel cancels. The legacy
// placeholder /checkout/sessions never existed on the real sandbox (it 404'd —
// SIN-65804/SIN-65883).
const checkoutPath = "/v1/checkouts"

// cardBody is the C6 payment.card object (schema: card). For the hosted checkout
// flow the payer types the card on C6's page, so card_info (card_hash/token) is
// never sent at creation — only the routing fields are. installments is fixed at 1
// (single payment) because the current product/port models no installment plan;
// multi-installment (with interest_type) is a future port field, not invented here.
type cardBody struct {
	Type         string `json:"type"`                   // DEBIT | CREDIT
	Installments int    `json:"installments"`           // 1..12
	Authenticate string `json:"authenticate,omitempty"` // REQUIRED | OPTIONAL | NOT_REQUIRED
}

// paymentBody is the C6 payment envelope (schema: payment). For a card checkout it
// carries the card object (a pix-only checkout would carry pix instead).
type paymentBody struct {
	Card *cardBody `json:"card,omitempty"`
}

// checkoutRequestBody is the JSON sent to C6 to open a hosted checkout (schema:
// checkout). The real contract is a single decimal amount in REAIS (brlDecimal,
// never cents) plus the payment method — there is no items[] array; our domain
// line items are summed into amount. external_reference_id/payer are optional (C6
// collects the payer on its page when omitted).
type checkoutRequestBody struct {
	Amount             brlDecimal  `json:"amount"`
	Payment            paymentBody `json:"payment"`
	ExpirationDateTime string      `json:"expiration_date_time,omitempty"`
}

// checkoutResponseBody is the subset of C6's checkout representation we consume. The
// create (201) response is {id, url}; the reconcile (GET 200) response is the full
// `checkout` schema — id, status, amount (decimal reais) and url. captured_amount is
// documented "EM BREVE" (not yet returned), so the adapter cannot reconcile by
// captured amount — see toCheckoutResult.
type checkoutResponseBody struct {
	ID     string     `json:"id"`
	Status string     `json:"status"`
	URL    string     `json:"url"`
	Amount brlDecimal `json:"amount"`
}

// CreateCheckoutSession opens a hosted checkout at C6 (POST /v1/checkouts/) and
// returns the hosted URL the caller sends the payer to. The domain session's line
// items are summed into the single `amount` C6 expects (decimal reais via
// brlDecimal); the permitted card method maps to payment.card.type and the step-up
// flag to payment.card.authenticate. The caller's IdempotencyKey (falling back to
// the SessionID) collapses retried openings; the per-tenant OAuth2 bearer is attached
// by authedJSONRequest.
func (p *Provider) CreateCheckoutSession(ctx context.Context, tenantID string, req ports.CheckoutRequest) (ports.CheckoutResult, error) {
	cardType := strings.ToUpper(strings.TrimSpace(req.CardType))
	if cardType != "CREDIT" && cardType != "DEBIT" {
		return ports.CheckoutResult{}, &Error{Op: "create_checkout", sentinel: shared.ErrValidation}
	}

	amounts := make([]int64, len(req.Items))
	for i, it := range req.Items {
		amounts[i] = it.AmountCents
	}
	sum, err := shared.SumCents(amounts...) // checked add — overflow fails closed (SIN-65706)
	if err != nil || sum <= 0 {
		return ports.CheckoutResult{}, &Error{Op: "create_checkout", sentinel: shared.ErrValidation}
	}

	authenticate := "NOT_REQUIRED"
	if req.RequireAuthentication {
		authenticate = "REQUIRED"
	}

	body := checkoutRequestBody{
		Amount: brlDecimal(sum),
		Payment: paymentBody{Card: &cardBody{
			Type:         cardType,
			Installments: 1,
			Authenticate: authenticate,
		}},
	}
	if !req.ExpiresAt.IsZero() {
		body.ExpirationDateTime = req.ExpiresAt.UTC().Format(time.RFC3339)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return ports.CheckoutResult{}, &Error{Op: "create_checkout", sentinel: shared.ErrValidation}
	}

	idem := req.IdempotencyKey
	if idem == "" {
		idem = req.SessionID
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_checkout", http.MethodPost, p.baseURL+checkoutPath+"/", payload, idem)
	if err != nil {
		return ports.CheckoutResult{}, err
	}

	var out checkoutResponseBody
	if err := p.do(httpReq, "create_checkout", &out); err != nil {
		return ports.CheckoutResult{}, err
	}
	// Defense-in-depth (open-redirect): the caller redirects the payer to this URL.
	// A tampered/compromised PSP could return a well-formed non-https / relative /
	// opaque target; refuse anything that is not an absolute https URL rather than
	// forward it. The raw value never leaks through the error.
	if err := validateRedirectURL(out.URL); err != nil {
		return ports.CheckoutResult{}, err
	}
	status := out.Status
	if status == "" {
		status = "CREATED" // create returns {id,url}; a fresh checkout is CREATED (spec)
	}
	return ports.CheckoutResult{
		SessionID:   out.ID,
		Status:      status,
		RedirectURL: out.URL,
		// AmountCents is the authorized total we sent (C6's create response does not
		// echo it); reflecting it keeps the result self-describing for the caller.
		AmountCents: sum,
		// Echo the permitted method back so the caller's response is self-describing
		// (C6's create response does not return them).
		CardType:              req.CardType,
		RequireAuthentication: req.RequireAuthentication,
	}, nil
}

// GetCheckoutSession reconciles the authoritative state of a checkout from C6 via
// GET /v1/checkouts/{id}. It is the source of truth for settlement — never trust a
// raw webhook (threat W3). A 404 surfaces as shared.ErrNotFound; the read is
// tenant-scoped through the per-tenant bearer. A redirect URL, when present, is
// validated (open-redirect defense).
func (p *Provider) GetCheckoutSession(ctx context.Context, tenantID, sessionID string) (ports.CheckoutResult, error) {
	endpoint := p.baseURL + checkoutPath + "/" + url.PathEscape(sessionID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "get_checkout", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.CheckoutResult{}, err
	}
	var out checkoutResponseBody
	if err := p.do(httpReq, "get_checkout", &out); err != nil {
		return ports.CheckoutResult{}, err
	}
	return toCheckoutResult(out, "get_checkout")
}

// CancelCheckoutSession cancels a checkout at C6 via PUT /v1/checkouts/{id}/cancel.
// C6 answers 204 No Content (no body), so the cancelled state is synthesized. Cancel
// is idempotent at C6 (an unpaid checkout is aborted, a paid one is refunded when the
// method allows). A 404 surfaces as shared.ErrNotFound (no cross-tenant oracle).
func (p *Provider) CancelCheckoutSession(ctx context.Context, tenantID, sessionID string) (ports.CheckoutResult, error) {
	endpoint := p.baseURL + checkoutPath + "/" + url.PathEscape(sessionID) + "/cancel"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "cancel_checkout", http.MethodPut, endpoint, nil, "")
	if err != nil {
		return ports.CheckoutResult{}, err
	}
	if err := p.doNoContent(httpReq, "cancel_checkout"); err != nil {
		return ports.CheckoutResult{}, err
	}
	return ports.CheckoutResult{SessionID: sessionID, Status: "CANCELLED"}, nil
}

// toCheckoutResult maps a reconcile (GET) response into the port result. The redirect
// URL is validated only when present (a cancelled/paid checkout need not carry one);
// an untrusted non-https/relative target fails closed rather than being forwarded.
//
// ReceivedAmountCents is left zero: C6 does not yet return a captured amount
// (captured_amount is documented "EM BREVE"), so the reconcile read cannot assert
// captured == authorized. AmountReconciled() then stays false, which is fail-safe for
// threat W3 — a checkout is never settled for an unverified captured amount. Amount-
// or status-based settlement of checkouts is a follow-up once C6 GA's captured_amount
// (settlement path, SIN-65726).
func toCheckoutResult(out checkoutResponseBody, op string) (ports.CheckoutResult, error) {
	if out.URL != "" {
		if err := validateRedirectURL(out.URL); err != nil {
			return ports.CheckoutResult{}, &Error{Op: op, detail: "untrusted redirect url", sentinel: shared.ErrUnavailable}
		}
	}
	return ports.CheckoutResult{
		SessionID:           out.ID,
		Status:              out.Status,
		RedirectURL:         out.URL,
		AmountCents:         int64(out.Amount),
		ReceivedAmountCents: 0,
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
