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

// compile-time assertion that Provider satisfies the consent port.
var _ ports.ConsentProvider = (*Provider)(nil)

// consentRequestBody is the JSON sent to C6 to register a PIX Automático consent.
// The validity window is transmitted as RFC3339 timestamps; an open-ended consent
// omits the end field entirely (omitempty on the zero time).
type consentRequestBody struct {
	ConsentID      string     `json:"consent_id"`
	DebtorTaxID    string     `json:"debtor_tax_id"`
	MaxAmountCents int64      `json:"max_amount_cents"`
	Currency       string     `json:"currency"`
	Frequency      string     `json:"frequency"`
	StartAt        time.Time  `json:"start_at"`
	EndAt          *time.Time `json:"end_at,omitempty"`
}

// consentResponseBody is the subset of C6's consent representation we consume.
type consentResponseBody struct {
	ConsentID string `json:"consent_id"`
	Status    string `json:"status"`
}

// CreateConsent registers a recurring-debit (PIX Automático) consent at C6. The
// caller's IdempotencyKey (falling back to the ConsentID) is forwarded so the PSP
// collapses retried/concurrent registrations into one consent. The OAuth2 bearer
// token is attached per tenant.
func (p *Provider) CreateConsent(ctx context.Context, tenantID string, req ports.ConsentRequest) (ports.ConsentResult, error) {
	body := consentRequestBody{
		ConsentID:      req.ConsentID,
		DebtorTaxID:    req.DebtorTaxID,
		MaxAmountCents: req.MaxAmountCents,
		Currency:       req.Currency,
		Frequency:      req.Frequency,
		StartAt:        req.StartAt,
	}
	if !req.EndAt.IsZero() {
		end := req.EndAt
		body.EndAt = &end
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return ports.ConsentResult{}, &Error{Op: "create_consent", sentinel: shared.ErrValidation}
	}

	idem := req.IdempotencyKey
	if idem == "" {
		idem = req.ConsentID
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_consent", http.MethodPost, p.baseURL+"/consents", payload, idem)
	if err != nil {
		return ports.ConsentResult{}, err
	}

	var out consentResponseBody
	if err := p.do(httpReq, "create_consent", &out); err != nil {
		return ports.ConsentResult{}, err
	}
	return ports.ConsentResult{ConsentID: out.ConsentID, Status: out.Status}, nil
}

// GetConsent reconciles the authoritative state of a consent from C6 (never trust
// a raw webhook — threat W3).
func (p *Provider) GetConsent(ctx context.Context, tenantID, consentID string) (ports.ConsentResult, error) {
	endpoint := p.baseURL + "/consents/" + url.PathEscape(consentID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "get_consent", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.ConsentResult{}, err
	}

	var out consentResponseBody
	if err := p.do(httpReq, "get_consent", &out); err != nil {
		return ports.ConsentResult{}, err
	}
	return ports.ConsentResult{ConsentID: out.ConsentID, Status: out.Status}, nil
}

// CancelConsent revokes a consent at C6 so no further debits can be originated.
// It is idempotent on the consent id: a repeat cancel is safe.
func (p *Provider) CancelConsent(ctx context.Context, tenantID, consentID string) (ports.ConsentResult, error) {
	endpoint := p.baseURL + "/consents/" + url.PathEscape(consentID) + "/cancel"
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "cancel_consent", http.MethodPost, endpoint, nil, consentID)
	if err != nil {
		return ports.ConsentResult{}, err
	}

	var out consentResponseBody
	if err := p.do(httpReq, "cancel_consent", &out); err != nil {
		return ports.ConsentResult{}, err
	}
	return ports.ConsentResult{ConsentID: out.ConsentID, Status: out.Status}, nil
}
