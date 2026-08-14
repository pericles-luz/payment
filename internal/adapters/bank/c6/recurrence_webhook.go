package c6

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Outbound recurrence webhook registration for the C6 adapter (PIX Automático,
// SIN-66036). The inbound receiver (/webhooks/c6/{tenantRef}/{rec,cobr}) is wired
// in the HTTP layer; this is the OUTBOUND half: telling C6 which HTTPS URL to POST
// recurrence notifications to. All HTTP/JSON lives here so the one-shot command and
// use-cases never speak the PSP wire shape (Hexagonal).
//
// Wire contract — BACEN "API Pix" v2 PIX Automático (the same spec C6 fronts for
// the cob/cobv/rec/cobr surfaces already mapped here, SIN-65856/66034). The two
// recurrence callbacks are SINGLETONS per recebedor — unlike the immediate-PIX
// webhook keyed per chave (/v2/pix/webhook/{chave}), these carry NO path key:
//   - PUT|GET /v2/pix/webhookrec  → mandate (Rec) status callback
//   - PUT|GET /v2/pix/webhookcobr → recurring charge (CobR) callback
//
// The body is a single {"webhookUrl": "https://…"}; PUT registers/replaces it
// (idempotent), GET reads it back ({"webhookUrl", "criacao"}). HTTPS is enforced at
// the boundary (a plaintext callback would expose the secret per-tenant ref the URL
// embeds and the notification in transit). The /v2/pix prefix matches the rec/cobr
// resource paths this adapter already drives (recPath/cobrPath).

const (
	// recWebhookPath is the BACEN PIX Automático Rec-status callback singleton:
	// PUT|GET /v2/pix/webhookrec (no path key — one per recebedor).
	recWebhookPath = "/v2/pix/webhookrec"
	// cobrWebhookPath is the BACEN PIX Automático CobR callback singleton:
	// PUT|GET /v2/pix/webhookcobr (no path key — one per recebedor).
	cobrWebhookPath = "/v2/pix/webhookcobr"
)

// compile-time assertion that Provider satisfies the recurrence-registrar port.
var _ ports.RecurrenceWebhookRegistrar = (*Provider)(nil)

// RegisterRecWebhook idempotently registers (PUT /v2/pix/webhookrec) the HTTPS URL
// C6 will POST mandate-status notifications to for the authenticated tenant. The
// registration is a singleton per recebedor (no path key), so a re-PUT replaces
// rather than duplicates. Complete mediation: an empty tenantID or non-HTTPS URL is
// refused before any call is made. The webhookURL embeds a secret per-tenant ref
// and is never logged or surfaced in an error.
func (p *Provider) RegisterRecWebhook(ctx context.Context, tenantID, webhookURL string) error {
	return p.registerRecurrenceWebhook(ctx, tenantID, webhookURL, recWebhookPath, "register_rec_webhook")
}

// GetRecWebhook reads back the Rec callback currently registered (GET
// /v2/pix/webhookrec) so a caller can confirm the registration idempotently. An
// unregistered tenant surfaces as shared.ErrNotFound. The returned WebhookURL
// embeds a secret ref and must never be logged.
func (p *Provider) GetRecWebhook(ctx context.Context, tenantID string) (ports.WebhookRegistration, error) {
	return p.getRecurrenceWebhook(ctx, tenantID, recWebhookPath, "get_rec_webhook")
}

// RegisterCobRWebhook idempotently registers (PUT /v2/pix/webhookcobr) the HTTPS
// URL C6 will POST recurring-charge notifications to for the authenticated tenant.
func (p *Provider) RegisterCobRWebhook(ctx context.Context, tenantID, webhookURL string) error {
	return p.registerRecurrenceWebhook(ctx, tenantID, webhookURL, cobrWebhookPath, "register_cobr_webhook")
}

// GetCobRWebhook reads back the CobR callback currently registered (GET
// /v2/pix/webhookcobr).
func (p *Provider) GetCobRWebhook(ctx context.Context, tenantID string) (ports.WebhookRegistration, error) {
	return p.getRecurrenceWebhook(ctx, tenantID, cobrWebhookPath, "get_cobr_webhook")
}

// registerRecurrenceWebhook is the shared PUT path for both singleton recurrence
// callbacks: it validates the tenant + HTTPS URL at the boundary, then PUTs the
// {"webhookUrl"} body to the no-key collection path. The per-tenant OAuth2 bearer
// scopes the registration to the tenant. The outcome is the HTTP status (the PSP
// answers with 200/201/204 and an empty/echo body), so the body is not decoded.
func (p *Provider) registerRecurrenceWebhook(ctx context.Context, tenantID, webhookURL, path, op string) error {
	if strings.TrimSpace(tenantID) == "" {
		return &Error{Op: op, sentinel: shared.ErrValidation, detail: "tenant is required"}
	}
	if !isHTTPSURL(webhookURL) {
		return &Error{Op: op, sentinel: shared.ErrValidation, detail: "webhook url must be https"}
	}
	payload, err := json.Marshal(webhookRequestBody{WebhookURL: webhookURL})
	if err != nil {
		return &Error{Op: op, sentinel: shared.ErrValidation}
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodPut, p.baseURL+path, payload, "")
	if err != nil {
		return err
	}
	return p.doStatus(httpReq, op)
}

// getRecurrenceWebhook is the shared GET path for both singleton recurrence
// callbacks. It is tenant-scoped through the per-tenant bearer; an unregistered
// callback surfaces as shared.ErrNotFound (via mapError on the 404).
func (p *Provider) getRecurrenceWebhook(ctx context.Context, tenantID, path, op string) (ports.WebhookRegistration, error) {
	if strings.TrimSpace(tenantID) == "" {
		return ports.WebhookRegistration{}, &Error{Op: op, sentinel: shared.ErrValidation, detail: "tenant is required"}
	}
	httpReq, err := p.authedJSONRequest(ctx, tenantID, op, http.MethodGet, p.baseURL+path, nil, "")
	if err != nil {
		return ports.WebhookRegistration{}, err
	}
	var out webhookResponseBody
	if err := p.do(httpReq, op, &out); err != nil {
		return ports.WebhookRegistration{}, err
	}
	return ports.WebhookRegistration{
		WebhookURL: out.WebhookURL,
		CreatedAt:  parseWebhookCreatedAt(out.Criacao),
	}, nil
}
