// Package c6 implements ports.BankProvider against the C6 bank (PSP). It owns all
// HTTP and OAuth2 concerns so the domain and use-cases never import net/http or a
// vendor SDK (Hexagonal). It is the foundation seam for the later C6 slices (PIX,
// PIX Automático, BolePix, Checkout, Webhook).
//
// Security posture (secure-by-default): HTTPS-only endpoints (non-HTTPS is
// rejected at construction), TLS >= 1.2, per-request timeouts and propagated
// context (no goroutine leak), per-tenant OAuth2 client_credentials tokens held
// only in memory, and errors that never leak the client secret or the raw PSP
// response body.
package c6

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// maxResponseBytes caps how much of an upstream response is read, bounding memory
// on a hostile or buggy PSP response.
const maxResponseBytes = 1 << 20 // 1 MiB

// defaultTimeout is the per-request timeout when Config.Timeout is unset.
const defaultTimeout = 15 * time.Second

// Config configures the C6 provider's transport. Endpoints are per-environment
// and supplied by the caller (from process config) — never hard-coded.
type Config struct {
	// BaseURL is the C6 REST API base (e.g. https://api.c6bank.example). Required.
	BaseURL string
	// TokenURL is the OAuth2 client_credentials token endpoint. Required.
	TokenURL string
	// Scope is an optional OAuth2 scope requested with the token.
	Scope string
	// Timeout is the per-request timeout. Defaults to defaultTimeout when zero.
	Timeout time.Duration
	// HTTPClient overrides the HTTP client (used in tests against httptest TLS
	// servers, or to inject an mTLS transport when the C6 docs require client
	// certificates). When nil a TLS-1.2+ client with Timeout is built.
	HTTPClient *http.Client
	// Now overrides the clock (token expiry). Defaults to time.Now.
	Now func() time.Time
	// BillingScheme is the C6 carteira de cobrança used on bank-slip registration
	// (production: 15, sandbox: 21 — per the C6 Bolepix contract). Empty selects
	// defaultBillingScheme.
	BillingScheme string
	// RecurrenceVerifier verifies the JWS-signed Recorrência reads (rec/solicrec/
	// cobr GETs return Accept: application/jose). When nil, those reads fail secure
	// (ErrUnavailable) rather than trusting an unverified mandate document. The
	// concrete verifier (JOSE lib + JWKS) is a dependency decision pending CTO
	// sign-off (SIN-66034 F0); the create/cancel paths do not need it.
	RecurrenceVerifier RecurrenceVerifier

	// RateLimitPerSecond is the steady-state outbound request rate (tokens/sec) to
	// C6, capping the load this adapter can generate (Termo A5, no DoS-shaped
	// traffic). Zero or negative ⇒ defaultRatePerSecond.
	RateLimitPerSecond float64
	// RateLimitBurst is the token-bucket capacity — the largest burst allowed
	// before RateLimitPerSecond applies. Zero or negative ⇒ defaultBurst.
	RateLimitBurst int
	// MaxRetries is the number of RETRIES on a retryable status (429/503). Zero ⇒
	// defaultMaxRetries; negative ⇒ no retries (single-shot). The ceiling is
	// deliberately small so a degraded PSP is never hammered (Termo A5).
	MaxRetries int
}

// Provider implements ports.BankProvider (and ports.PixProvider) against C6.
type Provider struct {
	baseURL string
	// billingScheme is the C6 "carteira de cobrança" sent on every bank-slip
	// registration. It is ENVIRONMENT-dependent (C6 documents carteira 15 in
	// production and 21 in sandbox), so it is configuration, never a constant: a
	// deployment pointed at the wrong environment must be fixed by config, not by a
	// rebuild. Defaults to defaultBillingScheme when unset.
	billingScheme string
	httpc         *http.Client
	tokens        *tokenManager
	// creds resolves a tenant's bank credential, including its registered PIX
	// creditor key (chave do recebedor), which the adapter injects into a cob/cobv
	// when the request omits one (per-tenant config injection, ADR-0004 /
	// SIN-65862). It is the same per-tenant store the token manager uses, so a
	// charge can never route funds under another tenant's identity (threat H1/P1).
	creds ports.CredentialStore
	// bankID is the slug this adapter instance is bound to ("c6"). The bank is fixed
	// in the adapter's identity, NOT carried on a business request, so the credential
	// lookup always resolves the (tenant, "c6") pair (ADR-0007 §3). This keeps the
	// multi-bank dimension confined to the credential boundary.
	bankID string
	// now is the clock used for PIX QR-expiry computation when the PSP omits the
	// charge creation timestamp. Defaults to time.Now (overridable for tests).
	now func() time.Time
	// recVerifier verifies JWS-signed Recorrência reads. Optional (nil ⇒ reads fail
	// secure); see Config.RecurrenceVerifier.
	recVerifier RecurrenceVerifier
	// limiter paces outbound requests to C6 (proactive token bucket, Termo A5). Non-nil.
	limiter *tokenBucket
	// maxRetries bounds retries on a retryable status (429/503); see Config.MaxRetries.
	maxRetries int
	// sleep waits between the limiter/backoff gates and the next attempt. Injected
	// so tests drive timing deterministically; defaults to realSleep.
	sleep sleepFunc
	// randFloat sources the backoff jitter in [0,1). Injectable for deterministic
	// tests; defaults to math/rand.Float64.
	randFloat func() float64
}

// compile-time assertion that Provider satisfies the port.
var _ ports.BankProvider = (*Provider)(nil)

// compile-time assertion that Provider can evict its per-tenant token cache when
// a credential is rotated/revoked (token-revocation-lag fix, ADR-0003).
var _ ports.CredentialInvalidator = (*Provider)(nil)

// InvalidateToken evicts any cached OAuth2 token for tenantID so the next bank
// call obtains a fresh token under the tenant's current credential. It is the
// adapter side of ports.CredentialInvalidator: the admin plane calls it right
// after a credential rotation/revocation to close the token-revocation lag
// (ADR-0003). Safe to call for an unknown tenant (no-op).
func (p *Provider) InvalidateToken(tenantID string) {
	p.tokens.invalidate(tenantID)
	// Uma rotação também precisa alcançar a camada TLS. O certificado de um tenant é
	// escolhido no handshake, então uma conexão que já está no pool continua
	// apresentando o certificado ANTIGO por tempo indefinido — a varredura de webhook
	// a mantém quente e ela nunca expira. Descartar o transporte do tenant faz a
	// próxima requisição discar do zero, com o certificado que acabou de ser gravado.
	if p.httpc != nil {
		if tr, ok := p.httpc.Transport.(*mtlsRoundTripper); ok {
			tr.dropTenant(tenantID)
		}
	}
}

// New validates the config and builds a Provider. Both endpoints must be absolute
// HTTPS URLs; an http:// or malformed endpoint is rejected (secure-by-default,
// TLS-only). creds resolves per-tenant OAuth2 credentials at token-fetch time.
func New(cfg Config, creds ports.CredentialStore) (*Provider, error) {
	if creds == nil {
		return nil, fmt.Errorf("c6: credential store is required")
	}
	if err := requireHTTPS("base_url", cfg.BaseURL); err != nil {
		return nil, err
	}
	if err := requireHTTPS("token_url", cfg.TokenURL); err != nil {
		return nil, err
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	httpc := cfg.HTTPClient
	if httpc == nil {
		httpc = defaultHTTPClient(timeout)
	}

	rate := cfg.RateLimitPerSecond
	if rate <= 0 {
		rate = defaultRatePerSecond
	}
	burst := cfg.RateLimitBurst
	if burst <= 0 {
		burst = defaultBurst
	}
	maxRetries := cfg.MaxRetries
	switch {
	case maxRetries == 0:
		maxRetries = defaultMaxRetries
	case maxRetries < 0:
		maxRetries = 0
	}

	billingScheme := strings.TrimSpace(cfg.BillingScheme)
	if billingScheme == "" {
		billingScheme = defaultBillingScheme
	}

	return &Provider{
		baseURL:       trimTrailingSlash(cfg.BaseURL),
		billingScheme: billingScheme,
		httpc:         httpc,
		tokens:        newTokenManager(creds, ports.BankIDC6, cfg.TokenURL, cfg.Scope, httpc, now),
		creds:         creds,
		bankID:        ports.BankIDC6,
		now:           now,
		recVerifier:   cfg.RecurrenceVerifier,
		limiter: &tokenBucket{
			tokens:       float64(burst),
			capacity:     float64(burst),
			refillPerSec: rate,
			now:          now,
		},
		maxRetries: maxRetries,
		sleep:      realSleep,
		randFloat:  rand.Float64,
	}, nil
}

// resolveCreditorKey returns the PIX key (chave do recebedor) a cob/cobv is
// registered under. A non-empty reqKey (the optional per-request override,
// reserved for a future multi-key hook) wins; otherwise the tenant's configured
// key (BankCredential.CreditorKey) is injected from the per-tenant store. Sourcing
// the key from per-tenant config instead of per-request input constrains fund
// routing to the tenant's registered account: a compromised or buggy app surface
// cannot reroute funds to an arbitrary PIX key (OWASP A01, confused-deputy
// defense; ADR-0004 / SIN-65862).
//
// A credential-store failure (e.g. unknown tenant) is propagated verbatim so the
// caller surfaces the same typed error it always has. When BOTH the request and
// the configured key are empty, the resolved key is "" and the caller currently
// omits the chave (the wire field is omitempty); turning that into a fail-fast
// adapter-boundary error is gated on CTO authorization to update the existing
// create-charge tests that omit a key (rule 3; tracked in SIN-65862).
func (p *Provider) resolveCreditorKey(ctx context.Context, tenantID, reqKey string) (string, error) {
	if k := strings.TrimSpace(reqKey); k != "" {
		return k, nil
	}
	cred, err := p.creds.GetBankCredential(ctx, tenantID, p.bankID)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(cred.CreditorKey), nil
}

// requireHTTPS rejects any endpoint that is not an absolute https:// URL. A
// non-TLS PSP endpoint would expose the bearer token and charge data in transit.
func requireHTTPS(field, raw string) error {
	if raw == "" {
		return fmt.Errorf("c6: %s is required", field)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("c6: %s is not a valid URL", field)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("c6: %s must be https (got %q)", field, u.Scheme)
	}
	return nil
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// defaultHTTPClient builds an HTTP client that enforces TLS >= 1.2 and a total
// per-request timeout. A bounded transport keeps idle connections in check so the
// adapter does not leak goroutines/sockets.
//
// Redirects are disabled: a payment-API client must never silently chase a 3xx
// (a form of SSRF, and the stdlib default of following up to 10 hops). Returning
// http.ErrUseLastResponse hands the 3xx response back to do() unfollowed, where
// sentinelForStatus maps it to ErrUnavailable — exactly as that comment intends
// ("incl. 3xx we did not follow"). Secure-by-default; F1 of SIN-64750 review.
func defaultHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
}

// idempotencyKey returns the key to forward to the PSP: the caller's
// IdempotencyKey when present, else the PaymentID as a deterministic fallback.
func idempotencyKey(req ports.ChargeRequest) string {
	if req.IdempotencyKey != "" {
		return req.IdempotencyKey
	}
	return req.PaymentID
}

// cobToChargeResult maps a BACEN cob representation into the generic charge port
// result, reconciling the money through the shared PIX mapping: valor.original is
// the expected amount and the sum of the pix[] receipts is what was received. It is
// fail-secure for settlement — an absent amount reconciles to zero cents (and
// AmountReconciled then refuses to settle), while a malformed amount maps to
// ErrUnavailable rather than being read as zero.
func (p *Provider) cobToChargeResult(b pixChargeResponseBody, op string) (ports.ChargeResult, error) {
	r, err := p.toPixResult(b, op)
	if err != nil {
		return ports.ChargeResult{}, err
	}
	return ports.ChargeResult{
		TxID:                r.TxID,
		Status:              r.Status,
		ExpectedAmountCents: r.ExpectedAmountCents,
		ReceivedAmountCents: r.ReceivedAmountCents,
	}, nil
}

// CreateCharge creates a charge at C6 against the BACEN PIX v2 immediate-charge
// (cob) surface — an idempotent PUT on /v2/pix/cob/{txid}. This is the real C6
// contract; the prior placeholder POST /charges 404'd against the sandbox
// (SIN-65856, live-verified). The txid is derived deterministically from the
// idempotency anchor so a re-submit targets the same resource (idempotent create)
// and matches the txid the settlement reconcile read (GetCharge / the
// PixSettlementProvider) addresses. The anchor is also forwarded as the
// Idempotency-Key header (F3b defense-in-depth, SIN-64720); the OAuth2 bearer is
// attached per tenant.
func (p *Provider) CreateCharge(ctx context.Context, tenantID string, req ports.ChargeRequest) (ports.ChargeResult, error) {
	// Complete mediation at the money seam (mirrors CreateImmediateCharge): an empty
	// idempotency anchor would derive the constant txid sha256("")[:32] and collide
	// distinct charges onto one resource; a non-positive amount is never a valid
	// charge. Fail securely at the boundary.
	if idempotencyKey(req) == "" || req.AmountCents <= 0 {
		return ports.ChargeResult{}, &Error{Op: "create_charge", sentinel: shared.ErrValidation}
	}
	txid := pixTxID(req)

	chave, err := p.resolveCreditorKey(ctx, tenantID, req.CreditorKey)
	if err != nil {
		return ports.ChargeResult{}, err
	}

	payload, err := json.Marshal(pixChargeRequestBody{
		Calendario: pixCalendario{Expiracao: int64(defaultPixExpiry / time.Second)},
		Devedor:    buildDevedor(req),
		Valor:      pixValor{Original: formatAmount(req.AmountCents)},
		Chave:      chave,
	})
	if err != nil {
		return ports.ChargeResult{}, &Error{Op: "create_charge", sentinel: shared.ErrValidation}
	}

	endpoint := p.baseURL + pixCobPath + "/" + url.PathEscape(txid)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "create_charge", http.MethodPut, endpoint, payload, idempotencyKey(req))
	if err != nil {
		return ports.ChargeResult{}, err
	}

	var out pixChargeResponseBody
	if err := p.do(httpReq, "create_charge", &out); err != nil {
		return ports.ChargeResult{}, err
	}
	return p.cobToChargeResult(out, "create_charge")
}

// GetCharge reconciles the authoritative state of a charge from C6 via the BACEN
// cob read (GET /v2/pix/cob/{txid}); never trust a raw webhook (threat W3).
func (p *Provider) GetCharge(ctx context.Context, tenantID, txID string) (ports.ChargeResult, error) {
	endpoint := p.baseURL + pixCobPath + "/" + url.PathEscape(txID)
	httpReq, err := p.authedJSONRequest(ctx, tenantID, "get_charge", http.MethodGet, endpoint, nil, "")
	if err != nil {
		return ports.ChargeResult{}, err
	}

	var out pixChargeResponseBody
	if err := p.do(httpReq, "get_charge", &out); err != nil {
		return ports.ChargeResult{}, err
	}
	return p.cobToChargeResult(out, "get_charge")
}

// authedJSONRequest builds an HTTP request for tenant carrying a fresh per-tenant
// OAuth2 bearer token and JSON Accept/Content-Type headers. When body is non-nil
// it is sent as the JSON request body. idem, when non-empty, is forwarded as the
// PSP Idempotency-Key so retried/concurrent writes collapse to one effect. It
// centralises the auth + header plumbing the consent/boleto/checkout operations
// share so each operation file stays focused on its own request/response shape.
func (p *Provider) authedJSONRequest(ctx context.Context, tenantID, op, method, endpoint string, body []byte, idem string) (*http.Request, error) {
	// Stamp the tenant so the mTLS transport presents this tenant's vault certificate
	// on the handshake (SIN-69368); harmless when the client is the plain/stub one.
	ctx = withTenant(ctx, tenantID)
	token, err := p.tokens.token(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, rdr)
	if err != nil {
		return nil, transportError(op)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	return req, nil
}

// do executes an authenticated request, maps a non-2xx into a domain error, and
// decodes a 2xx body into dst. The response body is always drained and closed and
// read under a size cap; raw body bytes never escape into an error.
//
// Two outbound-traffic controls wrap each attempt (defense in depth, Termo A5/B11):
//   - a proactive token-bucket limiter paces steady-state load to C6;
//   - a small, bounded retry on 429/503 with exponential backoff + jitter that
//     honors a server-sent Retry-After. Transport failures are NOT retried
//     (single-shot), preserving the adapter's no-retry-storm posture; only the two
//     explicit overload statuses are retried, up to p.maxRetries.
//
// The request carries the same Idempotency-Key on every attempt (set by
// authedJSONRequest), so a retried write collapses to a single effect at C6 and
// can never double-charge. The body is rewound via req.GetBody between attempts.
func (p *Provider) do(req *http.Request, op string, dst any) error {
	ctx := req.Context()
	for attempt := 0; ; attempt++ {
		if attempt > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return transportError(op)
			}
			req.Body = body
		}

		if p.limiter != nil {
			if err := p.limiter.wait(ctx, p.sleep); err != nil {
				return transportError(op)
			}
		}

		resp, err := p.httpc.Do(req)
		if err != nil {
			return transportError(op)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		status := resp.StatusCode
		retryAfter, hasRetryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), p.now())
		_ = resp.Body.Close()

		if status/100 == 2 {
			if err := json.Unmarshal(body, dst); err != nil {
				return &Error{Op: op, StatusCode: status, sentinel: shared.ErrUnavailable}
			}
			return nil
		}

		if isRetryableStatus(status) && attempt < p.maxRetries {
			if delay, ok := p.retryDelay(attempt, retryAfter, hasRetryAfter); ok {
				if err := p.sleep(ctx, delay); err != nil {
					return transportError(op)
				}
				continue
			}
		}
		return mapError(op, status, body)
	}
}
