package c6

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// C6-PROPRIETARY webhook registration (/v1/webhooks) — the sibling of the BACEN PIX
// surface in webhook.go, and the one that backs checkout and boleto notifications.
// C6 routes by the `service` discriminator in the body, NOT by the URL, so every
// service can (and should) point at the SAME per-tenant callback URL; the inbound
// receiver switches on the `service` field of the notification.
//
// Wire contract — live-discovered against the real C6 (SIN-69580), because the
// developer portal is login-gated and the runbook only ever recorded a shape:
//
//	POST /v1/webhooks              body {"service": "...", "url": "https://…"}
//	GET  /v1/webhooks?service=...  → the registration, 404 when none
//
// Three details cost a round-trip each to learn and are pinned by tests:
//
//   - POST, never PUT. C6 answers a PUT with 400 "PUT operation not allowed on path".
//   - Both fields are required; C6 names them itself when absent
//     ("Object has missing required properties ([\"service\",\"url\"])").
//   - Accept MUST be application/json — the OPPOSITE of the BACEN registration PUTs,
//     which demand application/problem+json (see webhookRegistrationAccept). Sending
//     problem+json here is rejected with "Must be one of: [application/json]". This is
//     why the Accept override lives on the BACEN calls only and never in the shared
//     request builder: the two families disagree.
const serviceWebhookPath = "/v1/webhooks"

// Service discriminators C6 accepts on this surface. They are the values the inbound
// notification echoes in its `service` field, which the receiver switches on.
const (
	ServiceCheckout    = "CHECKOUT"
	ServiceBankSlip    = "BANK_SLIP"
	ServiceBankSlipPix = "BANK_SLIP_PIX"
)

// knownServices is the closed allow-list validated at the adapter boundary, so a typo
// becomes a local validation error instead of an opaque PSP 400.
var knownServices = map[string]struct{}{
	ServiceCheckout:    {},
	ServiceBankSlip:    {},
	ServiceBankSlipPix: {},
}

// compile-time assertion that Provider satisfies the service-webhook port.
var _ ports.ServiceWebhookRegistrar = (*Provider)(nil)

// serviceWebhookRequest is the registration payload: the service discriminator plus the
// HTTPS callback URL. Note the field is `url` here, while the BACEN surface calls it
// `webhookUrl` — another place the two families disagree.
type serviceWebhookRequest struct {
	Service string `json:"service"`
	URL     string `json:"url"`
}

// serviceWebhookResponse is read back defensively: the registered URL has been observed
// under `url`, and `webhookUrl` is accepted as an alias so a PSP-side rename does not
// turn a working confirmation into a hard failure.
type serviceWebhookResponse struct {
	URL        string `json:"url"`
	WebhookURL string `json:"webhookUrl"`
}

func (r serviceWebhookResponse) callback() string {
	if r.URL != "" {
		return r.URL
	}
	return r.WebhookURL
}

// RegisterServiceWebhook registers the HTTPS callback C6 will POST notifications of
// `service` to, for the authenticated tenant. Complete mediation: an empty tenant, an
// unknown service, or a non-HTTPS URL is refused before any call is made. The URL embeds
// a secret per-tenant ref and is never logged or surfaced in an error.
func (p *Provider) RegisterServiceWebhook(ctx context.Context, tenantID, service, webhookURL string) error {
	const op = "register_service_webhook"
	service = strings.ToUpper(strings.TrimSpace(service))
	if strings.TrimSpace(tenantID) == "" {
		return &Error{Op: op, sentinel: shared.ErrValidation, detail: "tenant is required"}
	}
	if _, ok := knownServices[service]; !ok {
		return &Error{Op: op, sentinel: shared.ErrValidation, detail: "unknown service"}
	}
	if !isHTTPSURL(webhookURL) {
		return &Error{Op: op, sentinel: shared.ErrValidation, detail: "webhook url must be https"}
	}
	payload, err := json.Marshal(serviceWebhookRequest{Service: service, URL: webhookURL})
	if err != nil {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	// POST, not PUT (C6 rejects PUT on this path). The shared builder's default
	// Accept: application/json is exactly what this family requires — do NOT apply the
	// BACEN problem+json override here.
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPost, p.baseURL+serviceWebhookPath, payload, "")
	if err != nil {
		return err
	}
	return p.doStatus(httpReq, op)
}

// GetServiceWebhook reads back the callback currently registered for `service` so a
// caller can confirm a registration idempotently. An unregistered service surfaces as
// shared.ErrNotFound. The returned WebhookURL embeds a secret ref and must never be
// logged.
func (p *Provider) GetServiceWebhook(ctx context.Context, tenantID, service string) (ports.WebhookRegistration, error) {
	const op = "get_service_webhook"
	service = strings.ToUpper(strings.TrimSpace(service))
	if strings.TrimSpace(tenantID) == "" {
		return ports.WebhookRegistration{}, &Error{Op: op, sentinel: shared.ErrValidation, detail: "tenant is required"}
	}
	if _, ok := knownServices[service]; !ok {
		return ports.WebhookRegistration{}, &Error{Op: op, sentinel: shared.ErrValidation, detail: "unknown service"}
	}
	endpoint := p.baseURL + serviceWebhookPath + "?service=" + url.QueryEscape(service)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.WebhookRegistration{}, err
	}
	resp, err := p.httpc.Do(httpReq)
	if err != nil {
		return ports.WebhookRegistration{}, transportError(op)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode/100 != 2 {
		return ports.WebhookRegistration{}, mapError(op, resp.StatusCode, body)
	}
	var decoded serviceWebhookResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return ports.WebhookRegistration{}, &Error{Op: op, sentinel: shared.ErrUnavailable, detail: "malformed response"}
	}
	cb := decoded.callback()
	if cb == "" {
		return ports.WebhookRegistration{}, fmt.Errorf("%w: %s", shared.ErrNotFound, op)
	}
	return ports.WebhookRegistration{WebhookURL: cb}, nil
}
