package c6

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Outbound PIX webhook registration for the C6 adapter (SIN-65908). The inbound
// receiver (/webhooks/c6/{tenantRef}) is already up (SIN-65858); this is the
// OUTBOUND half: telling C6 which HTTPS URL to POST PIX settlement notifications
// to for a recebedor key (chave PIX). All HTTP/JSON lives here so the use-cases
// and the one-shot command never speak the PSP wire shape (Hexagonal).
//
// Wire contract — BACEN "API Pix" v2 webhook-by-key (the stable, public BCB
// contract C6 fronts): the callback is registered PER recebedor key, the key is
// carried in the PATH, and the body is a single {"webhookUrl": "https://…"}. PUT
// registers/replaces it (idempotent — re-PUTting the same URL does not duplicate);
// GET reads it back ({"webhookUrl", "criacao"}) so a caller can confirm. The path
// is namespaced under /v2/pix exactly like the cob/cobv surfaces this adapter
// already drives (live-discovered against the real C6 sandbox, SIN-65856), so the
// webhook collection is /v2/pix/webhook/{chave}.

const (
	// pixWebhookPath is the BACEN PIX v2 webhook-by-key collection path the C6
	// sandbox exposes: PUT/GET /v2/pix/webhook/{chave}. The /v2/pix prefix matches
	// the cob (pixCobPath) and cobv (pixCobvPath) surfaces the adapter already maps.
	pixWebhookPath = "/v2/pix/webhook"

	// webhookCriacaoLayout is the BACEN webhook creation-instant format echoed on a
	// GET. It is an RFC3339 timestamp; parsed best-effort (it is a cosmetic echo,
	// never settlement money, so a malformed value must not fail the read).
	webhookCriacaoLayout = time.RFC3339
)

// compile-time assertion that Provider satisfies the webhook-registrar port.
var _ ports.PixWebhookRegistrar = (*Provider)(nil)

// webhookRequestBody is the BACEN PIX webhook registration payload: the single
// HTTPS callback URL C6 will POST settlement notifications to for the recebedor
// key. The key (chave) is carried in the path, never the body.
type webhookRequestBody struct {
	WebhookURL string `json:"webhookUrl"`
}

// webhookResponseBody is the subset of C6's webhook representation read back on a
// GET (and echoed on a PUT): the registered callback URL and the PSP-assigned
// creation instant (consumed only as an opaque echo).
type webhookResponseBody struct {
	WebhookURL string `json:"webhookUrl"`
	Criacao    string `json:"criacao"`
}

// isHTTPSURL reports whether raw is an absolute https:// URL with a host. The C6
// PIX webhook MUST be HTTPS (an unsigned callback over plaintext would expose the
// secret per-tenant ref embedded in the path and the settlement notification in
// transit); a non-HTTPS URL is refused at the adapter boundary.
func isHTTPSURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != ""
}

// parseWebhookCreatedAt parses the BACEN "criacao" instant (RFC3339) best-effort;
// an absent or malformed value yields the zero time. The creation instant is a
// cosmetic echo for confirmation, never settlement truth, so a parse failure must
// not fail the read.
func parseWebhookCreatedAt(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(webhookCriacaoLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// RegisterWebhook idempotently registers the HTTPS webhookURL C6 will notify for
// the recebedor key pixKey, via a PUT on /v2/pix/webhook/{chave}. The registration
// is keyed by pixKey at the PSP, so re-running with the same URL replaces rather
// than duplicates (idempotent). Complete mediation at the boundary: an empty
// tenantID/pixKey or a non-HTTPS webhookURL is refused before any call is made
// (no upstream guard guarantees it). The per-tenant OAuth2 bearer is attached so
// the registration is scoped to the tenant; pixKey is also forwarded as the
// Idempotency-Key (defense-in-depth). The webhookURL embeds a secret per-tenant
// ref and is never logged or surfaced in an error.
func (p *Provider) RegisterWebhook(ctx context.Context, tenantID, pixKey, webhookURL string) error {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(pixKey) == "" {
		return &Error{Op: "register_webhook", sentinel: shared.ErrValidation, detail: "tenant and pix key are required"}
	}
	if !isHTTPSURL(webhookURL) {
		return &Error{Op: "register_webhook", sentinel: shared.ErrValidation, detail: "webhook url must be https"}
	}

	payload, err := json.Marshal(webhookRequestBody{WebhookURL: webhookURL})
	if err != nil {
		return &Error{Op: "register_webhook", sentinel: shared.ErrValidation}
	}

	endpoint := p.baseURL + pixWebhookPath + "/" + url.PathEscape(pixKey)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "register_webhook", http.MethodPut, endpoint, payload, pixKey)
	if err != nil {
		return err
	}
	// The PSP answers a successful PUT with 200/201/204 and an empty or echo body;
	// the registration outcome is the status, so the body is not decoded here.
	return p.doStatus(httpReq, "register_webhook")
}

// GetWebhook reads back the webhook currently registered for pixKey (GET
// /v2/pix/webhook/{chave}) so a caller can confirm the registration idempotently.
// An unregistered key surfaces as shared.ErrNotFound; the read is tenant-scoped
// through the per-tenant bearer. The returned WebhookURL embeds a secret ref and
// must never be logged.
func (p *Provider) GetWebhook(ctx context.Context, tenantID, pixKey string) (ports.WebhookRegistration, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(pixKey) == "" {
		return ports.WebhookRegistration{}, &Error{Op: "get_webhook", sentinel: shared.ErrValidation, detail: "tenant and pix key are required"}
	}

	endpoint := p.baseURL + pixWebhookPath + "/" + url.PathEscape(pixKey)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "get_webhook", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.WebhookRegistration{}, err
	}

	var out webhookResponseBody
	if err := p.do(httpReq, "get_webhook", &out); err != nil {
		return ports.WebhookRegistration{}, err
	}
	return ports.WebhookRegistration{
		WebhookURL: out.WebhookURL,
		CreatedAt:  parseWebhookCreatedAt(out.Criacao),
	}, nil
}

// doStatus executes an authenticated request and maps only the HTTP status: a
// non-2xx becomes the appropriate domain error; a 2xx (with any body, including an
// empty one) is success. It is the no-content sibling of do() for write operations
// whose outcome is the status, not a decoded representation. The body is drained
// under a size cap and closed; raw body bytes never escape into an error.
func (p *Provider) doStatus(req *http.Request, op string) error {
	resp, err := p.httpc.Do(req)
	if err != nil {
		return transportError(op)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode/100 != 2 {
		return mapError(op, resp.StatusCode, body)
	}
	return nil
}
