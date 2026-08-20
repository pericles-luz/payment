package http

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
	"github.com/ia-dev-sindireceita/payment/internal/version"
)

// Server holds the application services and authenticators behind the HTTP
// driving adapter. It is constructed once at startup and is safe for concurrent
// use.
type Server struct {
	charges   *app.ChargeService
	pix       *app.PixService
	pixCobV   *app.PixDueChargeService
	checkout  *app.CheckoutService
	boleto    *app.BoletoService
	dda       *app.DDAService
	statement *app.StatementService
	admin     *app.AdminService
	console   *app.ConsoleService
	// consoleAuth backs the self-contained console login (username + password +
	// TOTP, ADR-0001 Opção B / SIN-69265): first-access bootstrap, the login/logout
	// handlers, and the session validation the console auth middleware calls. When
	// nil the console falls back to Bearer-only auth (retrocompat): the login routes
	// still register but every login fails closed and only a valid admin Bearer opens
	// /console.
	consoleAuth *app.ConsoleAuthService
	ui          *adminweb.Renderer
	webhooks    *app.WebhookService
	tenantAuth  TenantPrincipalAuthenticator
	adminAuth   AdminPrincipalAuthenticator
	webhookAuth WebhookAuthenticator
	// accountResolver upgrades the account id stamped at the tenant choke-point
	// from the derived self-account to the tenant's REAL owning Account, read from
	// the tenant store (SIN-69222). When nil the choke-point keeps the self-account
	// default (retrocompat / single-tier deployments and tests).
	accountResolver AccountResolver
	csrf            CSRFGuard
	// bankResolver resolves and validates which bank a tenant request routes to
	// (multi-bank selector, SIN-66022). When nil the tenant plane runs single-bank:
	// no selector is read and every request resolves to the default bank.
	bankResolver *BankResolver
	// trustedProxyHops selects the spoof-resistant client-IP middleware installed
	// by Router (replaces chi middleware.RealIP). See Config.TrustedProxyHops.
	trustedProxyHops int
	// selfServeCredIntake gates the self-serve credential intake route
	// (PUT /v1/bank-credential, SIN-69196). Default false: the route is NOT
	// registered and the handler is inert unless this is explicitly enabled, so a
	// rollback is a config flip. See Config.SelfServeCredIntake.
	selfServeCredIntake bool
	// webhookLogPayload additionally logs the raw body of SUCCESSFULLY processed
	// inbound webhooks. Rejections log their body unconditionally regardless of this
	// flag. Default false. See Config.WebhookLogPayload.
	webhookLogPayload bool
	// accountKeyAuth authenticates an Account bearer key (model (b), ADR-0011 §2 /
	// SIN-69279). When nil OR accountKeySelector is false, the tenant choke-point
	// runs the unchanged model (a) path (tenant tokens only). See Config.AccountKeyAuth.
	accountKeyAuth AccountKeyAuthenticator
	// accountKeySelector gates the model (b) account-key + per-request selector auth
	// path. Default false (dark-ship): the key/selector are ignored and the
	// choke-point behaves exactly as today. See Config.AccountKeySelector.
	accountKeySelector bool
	// accountKeyMint mints/rotates an Account's bearer key for the emission routes
	// (POST /v1/account-key self-serve + POST /admin/accounts/{id}/account-key
	// bootstrap, model (b) / SIN-69280). Consulted only when model (b) is enabled
	// (accountKeySelector on AND accountKeyAuth wired); when nil the /v1 route is not
	// registered and the admin route fails closed (503). See Config.AccountKeyMint.
	accountKeyMint AccountKeyMinter
	// clientProvisioner provisions an empresa-cliente (tenant) owned by the calling
	// Account for the account-plane self-serve route (POST /v1/clients, model (b) /
	// SIN-69281). Consulted only when model (b) is enabled (accountKeySelector on AND
	// accountKeyAuth wired); when nil the route is registered under that gate but
	// fails closed (503). See Config.ClientProvisioner.
	clientProvisioner ClientProvisioner
	// accountOutboundWebhook gates the per-Conta OUTBOUND webhook config console CRUD
	// (SIN-69490, F0 of SIN-69486). Default false (dark-ship): when off the "Webhook de
	// saída" card is hidden and its set/rotate/remove routes are NOT registered, so the
	// current flow is entirely unaffected and rollback is a config flip. Config only —
	// no forwarding in F0. See Config.AccountOutboundWebhook.
	accountOutboundWebhook bool
	// webhookReg registers a self-serve client's PIX settlement webhook with C6 in-flow
	// once its credential + PIX key complete (SIN-69560 / F2). Best-effort: a failure
	// never affects the write response. When nil (stub bank / feature not wired) the
	// self-serve write paths skip the registration entirely. See Config.WebhookRegistrar.
	webhookReg WebhookInFlowRegistrar
	// bankCaps answers which payment methods a tenant's bank credential authorises, so
	// an empresa-cliente can configure only what its conta actually contratou. Optional:
	// nil makes GET /v1/bank-capabilities answer 503 rather than guess.
	bankCaps ports.BankCapabilityReader
}

// WebhookInFlowRegistrar is the narrow slice of app.WebhookRegistrationService the
// self-serve write handlers invoke to register a client's PIX webhook with C6 the
// moment its credential + PIX key are both in place (SIN-69560 / F2). It is
// best-effort by contract: TryRegister returns nothing, so a PSP failure can never
// turn a successful credential/certificate/key write into an error for the caller.
type WebhookInFlowRegistrar interface {
	TryRegister(ctx context.Context, tenantID string)
}

// Config wires a Server's dependencies. Console and UI back the HTML admin
// console (SIN-64727); they may be nil for deployments/tests that serve only the
// JSON planes — the console routes are then registered but never exercised.
type Config struct {
	Charges *app.ChargeService
	// Pix backs the immediate-PIX-charge tenant routes (/v1/pix). It may be nil for
	// deployments/tests that do not serve the PIX surface — the routes are then
	// registered but never exercised.
	Pix *app.PixService
	// PixCobV backs the PIX cobrança-com-vencimento tenant routes (/v1/pix/cobv). It
	// may be nil for deployments/tests that do not serve the cobv surface — the routes
	// are then registered but never exercised.
	PixCobV *app.PixDueChargeService
	// Checkout backs the unified hosted-checkout tenant route (POST /v1/checkout). It
	// may be nil for deployments/tests that do not serve checkout — the route is then
	// registered but never exercised.
	Checkout *app.CheckoutService
	// Boleto backs the BolePix boleto tenant routes (/v1/boletos). It may be nil for
	// deployments/tests that do not serve the boleto surface — the routes are then
	// registered but never exercised.
	Boleto *app.BoletoService
	// DDA backs the DDA / agendamento-de-pagamentos tenant routes (/v1/dda, roteiro
	// grupo 8). It may be nil for deployments/tests that do not serve the DDA surface —
	// the routes are then registered but never exercised.
	DDA *app.DDAService
	// Statement backs the account-statement tenant route (GET /v1/statement, roteiro
	// grupo 13). It may be nil for deployments/tests that do not serve the extrato
	// surface — the route is then registered but never exercised.
	Statement *app.StatementService
	Admin     *app.AdminService
	Console   *app.ConsoleService
	// ConsoleAuth wires the self-contained console login (SIN-69265). Optional: when
	// nil the console stays Bearer-only (the login form renders but always fails, and
	// only a valid admin Bearer opens /console) — used by tests and by deployments
	// that keep the proxy-injected-bearer transport (ADR-0001 Opção A).
	ConsoleAuth *app.ConsoleAuthService
	UI          *adminweb.Renderer
	Webhooks    *app.WebhookService
	TenantAuth  TenantPrincipalAuthenticator
	AdminAuth   AdminPrincipalAuthenticator
	WebhookAuth WebhookAuthenticator
	// AccountResolver resolves a tenant's REAL owning Account at the tenant auth
	// choke-point so ledger.account_id reflects the admin grouping (two-level
	// tenancy "Uso por Conta", SIN-69222). Built over the tenant read store
	// (NewStoreAccountResolver). When nil the choke-point keeps the self-account
	// default (acct-<tid>) — used by tests and single-tier deployments; behaviour
	// is then identical to before this port existed.
	AccountResolver AccountResolver
	// BankResolver resolves and validates the per-request bank selector for the
	// tenant plane (multi-bank routing, SIN-66022). It is built from the wired bank
	// registry and the credential store. When nil, the tenant plane runs single-bank
	// (every request routes to the default bank) — used by tests that exercise a
	// single provider directly.
	BankResolver *BankResolver
	// SecureCookies sets the Secure attribute on cookies this adapter issues
	// (CSRF token; the admin-UI session cookie via Server.CSRF). Driven by config
	// because TLS is terminated at a proxy — see config.Config.SecureCookies.
	SecureCookies bool
	// TrustedProxyHops is the number of trusted reverse proxies in front of this
	// service; it selects how the client IP (rate-limit key, IP attribution) is
	// derived. 0 (default) trusts only the TCP peer and ignores forwarding
	// headers (spoof-proof); N≥1 trusts exactly N proxy hops of X-Forwarded-For.
	// See config.Config.TrustedProxyHops — this replaces the spoofable
	// middleware.RealIP (GO-2026-5775).
	TrustedProxyHops int
	// SelfServeCredIntake enables the self-serve credential intake route
	// (PUT /v1/bank-credential, SIN-69196 / trilha E2). Default false (secure /
	// dark-ship): when off the route is not registered at all — the feature is
	// inert and rollback is a config flip. Wired from PAYMENT_SELFSERVE_CRED_INTAKE.
	// It does NOT block the go-live (go-live provisions credentials via the admin
	// intake); it is a fast-follow tenant convenience.
	SelfServeCredIntake bool
	// WebhookLogPayload logs the RAW body of successfully processed inbound webhooks
	// (PAYMENT_WEBHOOK_LOG_PAYLOAD, default false). It does NOT gate the logging of
	// REJECTED webhooks, whose body is always recorded: a rejection is a case the
	// receiver does not understand, and silent 400s previously made a live settlement
	// outage look like the PSP not calling at all (SIN-69580).
	//
	// Enable this only deliberately and time-boxed. The payload is written unredacted,
	// so on the accepted path — which is the high-volume one — it puts payer names and
	// tax ids into the log for every settled payment.
	WebhookLogPayload bool
	// AccountKeyAuth authenticates an Account's rotatable bearer key at the tenant
	// choke-point (model (b), ADR-0011 §2 / SIN-69279). Built over the account-key
	// store (ports.AccountKeyStore). It is consulted ONLY when AccountKeySelector is
	// true and the presented bearer has the account-key shape; otherwise it is
	// inert. When nil the account-key path stays off regardless of the flag
	// (fail-closed). Optional: tests and model (a) deployments leave it nil.
	AccountKeyAuth AccountKeyAuthenticator
	// AccountKeySelector enables the model (b) account-key + per-request client
	// selector auth path (ADR-0011 §2 / SIN-69279). Default false (secure /
	// dark-ship): the choke-point ignores the key/selector and behaves EXACTLY as
	// model (a). It deliberately reintroduces the A01/IDOR surface model (a)
	// designed out, so the per-request guard is load-bearing — keep it off until the
	// guard is security-reviewed for a deployment. Wired from PAYMENT_ACCOUNT_KEY_SELECTOR.
	AccountKeySelector bool
	// AccountKeyMint mints/rotates an Account's bearer key for the model (b) emission
	// routes (POST /v1/account-key self-rotate + POST /admin/accounts/{id}/account-key
	// bootstrap, ADR-0011 §3 / SIN-69280). Built over app.NewAccountKeyService atop
	// the account-key store. The /v1 self-rotate route is registered ONLY when model
	// (b) is enabled (AccountKeySelector && AccountKeyAuth != nil); the admin
	// bootstrap route is always registered but fails closed (503) when this is nil.
	// Optional: tests and model (a) deployments leave it nil.
	AccountKeyMint AccountKeyMinter
	// ClientProvisioner provisions an empresa-cliente (tenant) already bound to the
	// calling Account for the model (b) self-serve route (POST /v1/clients, ADR-0011
	// §4 / SIN-69281). Built over app.NewClientProvisioningService atop the tenant
	// repository. The route is registered ONLY when model (b) is enabled
	// (AccountKeySelector && AccountKeyAuth != nil); when this is nil the route fails
	// closed (503). Optional: tests and model (a) deployments leave it nil.
	ClientProvisioner ClientProvisioner
	// AccountOutboundWebhook gates the per-Conta OUTBOUND webhook config console CRUD
	// (SIN-69490, F0 of SIN-69486). Default false (dark-ship): off hides the card and
	// leaves the set/rotate/remove routes unregistered, so the current flow is
	// unaffected. Config only — no forwarding in F0.
	AccountOutboundWebhook bool
	// WebhookRegistrar registers a self-serve empresa-cliente's PIX settlement webhook
	// with C6 in-flow the moment its credential + PIX key complete (SIN-69560 / F2 of
	// SIN-69558). Built over app.NewWebhookRegistrationService atop the credential vault,
	// the C6 registrar, and the F1 ref minter. Best-effort by contract. Optional: when
	// nil (stub bank / feature not wired, e.g. tests and stub deployments) the self-serve
	// write paths skip the registration entirely.
	WebhookRegistrar WebhookInFlowRegistrar
	// BankCapabilities resolves a tenant's authorised payment methods from the bank.
	// Optional; nil disables GET /v1/bank-capabilities (503).
	BankCapabilities ports.BankCapabilityReader
}

// NewServer builds a Server from its config.
func NewServer(c Config) *Server {
	return &Server{
		charges:                c.Charges,
		pix:                    c.Pix,
		pixCobV:                c.PixCobV,
		checkout:               c.Checkout,
		boleto:                 c.Boleto,
		dda:                    c.DDA,
		statement:              c.Statement,
		admin:                  c.Admin,
		console:                c.Console,
		consoleAuth:            c.ConsoleAuth,
		ui:                     c.UI,
		webhooks:               c.Webhooks,
		tenantAuth:             c.TenantAuth,
		adminAuth:              c.AdminAuth,
		webhookAuth:            c.WebhookAuth,
		accountResolver:        c.AccountResolver,
		csrf:                   NewCSRFGuard(c.SecureCookies),
		bankResolver:           c.BankResolver,
		trustedProxyHops:       c.TrustedProxyHops,
		selfServeCredIntake:    c.SelfServeCredIntake,
		webhookLogPayload:      c.WebhookLogPayload,
		accountKeyAuth:         c.AccountKeyAuth,
		accountKeySelector:     c.AccountKeySelector,
		accountKeyMint:         c.AccountKeyMint,
		clientProvisioner:      c.ClientProvisioner,
		accountOutboundWebhook: c.AccountOutboundWebhook,
		webhookReg:             c.WebhookRegistrar,
		bankCaps:               c.BankCapabilities,
	}
}

// clientIPMiddleware returns the spoof-resistant client-IP middleware for the
// configured trusted-proxy depth. It replaces chi's middleware.RealIP, which
// blindly trusted the leftmost X-Forwarded-For value and was spoofable
// (GO-2026-5775). Both variants store the resolved IP on the request context;
// clientIP reads it via middleware.GetClientIP.
//
//   - hops == 0: ClientIPFromRemoteAddr — ignore all forwarding headers and use
//     the TCP peer. Spoof-proof; the secure default.
//   - hops >= 1: ClientIPFromXFFTrustedProxies(hops) — read the entry the
//     outermost trusted proxy added to X-Forwarded-For, the only entry a client
//     cannot forge past our own proxies.
func clientIPMiddleware(hops int) func(http.Handler) http.Handler {
	if hops < 1 {
		return middleware.ClientIPFromRemoteAddr
	}
	return middleware.ClientIPFromXFFTrustedProxies(hops)
}

// CSRF returns the server's CSRF guard so the admin-UI child can wrap its live
// HTML routes with Protect under the configured Secure-cookie policy.
func (s *Server) CSRF() CSRFGuard { return s.csrf }

// Router builds the HTTP handler. All routes are authenticated (deny-by-default);
// the public health check is the only unauthenticated route.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	// Spoof-resistant client IP (replaces the deprecated, spoofable
	// middleware.RealIP — GO-2026-5775). Installed before the rate limiters so
	// clientIP keys on a value a client cannot forge. See clientIPMiddleware.
	r.Use(clientIPMiddleware(s.trustedProxyHops))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(15 * time.Second))

	// Rate limiters: generous defaults; tune per deployment. The admin plane is
	// the most privileged surface (tenant creation, per-tenant bank-credential
	// writes), so it is limited at least as strictly as the tenant plane.
	tenantLimiter := newRateLimiter(20, 10, nil)
	adminLimiter := newRateLimiter(20, 10, nil)
	// The HTML console drives the same privileged admin operations as the JSON
	// admin plane (tenant creation, bank-credential writes, price sets), so it gets
	// its own limiter with the same budget (SIN-64741 L1). A separate bucket keeps a
	// console burst from throttling the JSON admin API and vice versa.
	consoleLimiter := newRateLimiter(20, 10, nil)
	// The public console login/bootstrap surface (SIN-69265) is unauthenticated, so
	// it gets its own tight per-IP limiter as the first-line anti-brute-force
	// control (the per-username lockout in ConsoleAuthService is the second). A small
	// burst tolerates the GET-then-POST of one honest login while throttling
	// credential-stuffing from a single origin.
	loginLimiter := newRateLimiter(10, 1, nil)
	webhookLimiter := newRateLimiter(50, 25, nil)

	// Public health check (the only unauthenticated route). It also surfaces the
	// build provenance (version/commit/built_at) so the CD smoke gate can assert
	// the deployed SHA actually went live, not just that *some* binary answers.
	// version.Info() carries no secrets — only the git SHA, tag, and build time —
	// so it is safe on an unauthenticated endpoint.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		b := version.Info()
		writeJSON(w, http.StatusOK, map[string]string{
			"status":   "ok",
			"version":  b.Version,
			"commit":   b.Commit,
			"built_at": b.BuiltAt,
		})
	})

	// Tenant API (TB1) — authenticated, tenant-scoped, rate-limited.
	r.Route("/v1", func(r chi.Router) {
		// Account-key self-rotation (model (b), ADR-0011 §3 / SIN-69280): the Account
		// rotates its OWN bearer key using its EXISTING key. It is authenticated by the
		// account-key bearer itself (accountKeyAuthMiddleware) with NO tenant selector —
		// this is the account plane acting on itself, not a tenant-scoped resource — so
		// it lives in its OWN group that does NOT inherit the tenant choke-point below.
		// Registered only in model (b) (flag on AND a key authenticator wired), so with
		// the flag off the route does not exist (rollback = config flip). It carries a
		// dedicated inbound limiter keyed on the Account (429 + Retry-After, fail-open),
		// mirroring the self-serve credential intake: a rare, high-value credential
		// write must not be masked by ordinary traffic and vice versa.
		if s.accountKeySelector && s.accountKeyAuth != nil {
			r.Group(func(r chi.Router) {
				const (
					akRotateBurst      = 5          // ≤5 rotations in a burst
					akRotateRefillPS   = 1.0 / 60.0 // ~1 token/minute sustained
					akRotateRetryAfter = 60         // seconds advertised on a 429
				)
				r.Use(accountKeyAuthMiddleware(s.accountKeyAuth))
				r.Use(newRateLimiter(akRotateBurst, akRotateRefillPS, nil).middlewareAccountKeyRotate(akRotateRetryAfter))
				r.Post("/account-key", s.handleRotateAccountKey)
			})

			// Empresa-cliente provisioning (model (b), ADR-0011 §4 / SIN-69281): a reseller
			// Conta creates a new empresa-cliente (tenant) bound to ITS OWN Account and gets
			// back the tenant id for the X-Client-Tenant selector. Like the account-key
			// route it is authenticated by the account-key bearer itself
			// (accountKeyAuthMiddleware) with NO tenant selector — the Account acts on itself
			// to create a tenant that does not exist yet — so it lives in its OWN group that
			// does NOT inherit the tenant choke-point below. The owning Account is taken from
			// the authenticated context, never the body (A01/T6). Registered only in model
			// (b) (flag on AND a key authenticator wired); a dedicated inbound limiter keyed
			// on the Account (429 + Retry-After, fail-open) keeps this rare, high-value write
			// from being masked by ordinary traffic and vice versa.
			r.Group(func(r chi.Router) {
				const (
					clientProvBurst      = 10         // ≤10 provisions in a burst (onboarding)
					clientProvRefillPS   = 1.0 / 60.0 // ~1 token/minute sustained
					clientProvRetryAfter = 60         // seconds advertised on a 429
				)
				r.Use(accountKeyAuthMiddleware(s.accountKeyAuth))
				r.Use(newRateLimiter(clientProvBurst, clientProvRefillPS, nil).middlewareClientProvision(clientProvRetryAfter))
				r.Post("/clients", s.handleProvisionClient)
			})
		}

		// Tenant-scoped routes — their own group so the tenant choke-point middleware is
		// scoped here and does NOT apply to the account-key group above.
		r.Group(func(r chi.Router) {
			// Model (b) account-key + per-request selector (ADR-0011 §2 / SIN-69279):
			// when the flag is on AND a key authenticator is wired, install the
			// selector-aware choke-point so an Account bearer key + X-Client-Tenant is
			// authorized by the load-bearing §2 guard. Default (flag off / no key auth):
			// the plain model (a) choke-point, byte-for-byte unchanged.
			if s.accountKeySelector && s.accountKeyAuth != nil {
				r.Use(tenantAuthMiddlewareWithSelector(s.tenantAuth, accountKeyGuard{enabled: true, keyAuth: s.accountKeyAuth}, s.accountResolver))
			} else {
				r.Use(tenantAuthMiddleware(s.tenantAuth, s.accountResolver))
			}
			// Multi-bank routing (SIN-66022): resolve and validate the per-request bank
			// selector right after the tenant is authenticated, so the resolved bank is
			// stamped on the context for the output-port routers. Runs before the limiter
			// so an unknown/unconfigured explicit bank is rejected with the uniform
			// not-found error. Omitted in single-bank deployments (nil resolver).
			if s.bankResolver != nil {
				r.Use(bankRouteMiddleware(s.bankResolver))
			}
			r.Use(tenantLimiter.middleware(tenantOrIPKey))
			r.Post("/charges", s.handleCreateCharge)
			r.Get("/charges/{id}", s.handleGetCharge)
			// Immediate PIX charges (cobrança imediata, roteiro 7.1–7.4). Create reserves
			// idempotently and bills; get/list reconcile from the PSP. List by date window
			// (?start&end) is registered before the {txid} read so chi routes them apart.
			r.Post("/pix", s.handleCreatePix)
			r.Get("/pix", s.handleListPix)
			// PIX cobrança com vencimento (cobv, roteiro 7.5–7.8): criar (7.5), consultar
			// (7.6), alterar (7.7). The static "/pix/cobv" segment is registered before the
			// immediate-charge "/pix/{txid}" read so chi routes the literal "cobv" segment
			// apart from a txid. Create generates the txid server-side (like immediate pix);
			// get/update address it. Settlement notification (7.8) is reconciled through the
			// shared C6 webhook (/webhooks/c6/{tenantRef}, C6-D), not a per-charge endpoint.
			r.Post("/pix/cobv", s.handleCreatePixCobV)
			r.Get("/pix/cobv/{txid}", s.handleGetPixCobV)
			r.Put("/pix/cobv/{txid}", s.handleUpdatePixCobV)
			r.Get("/pix/{txid}", s.handleGetPix)
			// Unified hosted checkout — open a session (roteiro 9.a–9.c), reconcile it
			// (grupo 10, GET) and cancel it (grupo 11, DELETE). The status webhook (grupo
			// 12) reuses the shared /webhooks/c6/{tenantRef} handler below.
			r.Post("/checkout", s.handleCreateCheckout)
			r.Get("/checkout/{id}", s.handleGetCheckout)
			r.Delete("/checkout/{id}", s.handleCancelCheckout)
			// BolePix boletos — full lifecycle: register with fine/interest/discount
			// variants (grupos 1–3), read by id (6.a), baixa/cancelamento (DELETE, grupo
			// 4) and alteração de vencimento/validade/valor (PUT, grupo 5).
			r.Post("/boletos", s.handleCreateBoleto)
			r.Get("/boletos/{id}", s.handleGetBoleto)
			r.Delete("/boletos/{id}", s.handleDeleteBoleto)
			r.Put("/boletos/{id}", s.handleUpdateBoleto)
			// DDA / agendamento de pagamentos (roteiro grupo 8): list the boletos open in
			// the tenant's DDA (8.1), submit a payment group for the initial consult (8.2),
			// read its items (8.3), trim items as a list (8.4) or one at a time (8.5) and
			// submit the group for approval (8.6). The {id}/{itemID} path params are
			// tenant-scoped in the use-case (a group owned by another tenant is 404, never a
			// cross-tenant existence oracle).
			r.Get("/dda/boletos", s.handleListDDABoletos)
			r.Post("/dda/payment-groups", s.handleCreateDDAGroup)
			r.Get("/dda/payment-groups/{id}/items", s.handleGetDDAGroupItems)
			r.Delete("/dda/payment-groups/{id}/items", s.handleRemoveDDAGroupItems)
			r.Delete("/dda/payment-groups/{id}/items/{itemID}", s.handleRemoveDDAGroupItem)
			r.Post("/dda/payment-groups/{id}/submit", s.handleSubmitDDAGroup)
			// Account statement (extrato, roteiro grupo 13): read the entries posted to the
			// authenticated tenant's account over a period (inicio/fim, máx. 30 dias, 13.a).
			// The tenant is derived from the credential, never the query — no parameter
			// selects which tenant's extrato is read (threat H1/P1).
			r.Get("/statement", s.handleGetStatement)

			// Capacidades do banco por tenant (SIN-69368). Deliberadamente FORA da flag de
			// intake self-serve: aquela flag protege ESCRITAS de segredo, e esta é uma
			// leitura que a loja precisa para montar a tela de pagamento. Prendê-la à mesma
			// flag faria a tela depender de uma chave que existe por outro motivo.
			r.Get("/bank-capabilities", s.handleTenantBankCapabilities)

			// Self-serve credential intake (SIN-69196 / trilha E2, flag-gated). An
			// empresa-cliente rotates its OWN bank credential with its tenant token; the
			// tenant is the authenticated caller (no selector → A01 designed out). It is
			// registered ONLY when the flag is on, so with the flag off the route does not
			// exist (rollback = config flip). It carries its OWN dedicated inbound limiter
			// (Q1): a tight per-tenant bucket (burst 5, ~1 req/min) that emits Retry-After
			// on a 429 and fails open on an internal fault — deliberately separate from the
			// tenant-plane limiter above and from the outbound C6 limiter (SIN-68742), so a
			// rare high-value credential write cannot be masked by ordinary traffic and
			// vice versa.
			if s.selfServeCredIntake {
				r.Group(func(r chi.Router) {
					const (
						selfServeBurst      = 5          // ≤5 rotations in a burst
						selfServeRefillPS   = 1.0 / 60.0 // ~1 token/minute sustained
						selfServeRetryAfter = 60         // seconds advertised on a 429
					)
					r.Use(newRateLimiter(selfServeBurst, selfServeRefillPS, nil).middlewareSelfServeCred(selfServeRetryAfter))
					r.Put("/bank-credential", s.handleTenantSetBankCredential)
					// A chave PIX completa o par com a credencial: sem ela o
					// adaptador não sabe para qual conta rotear os fundos.
					r.Put("/pix-key", s.handleTenantSetCreditorKey)
				})
				// Self-serve mTLS certificate intake (SIN-69346), the certificate sibling of
				// the credential intake above. Same flag (one Verz onboarding surface), same
				// A01-by-construction posture (tenant = authenticated caller, no selector),
				// same {c6} self-serve allow-list. It carries its OWN dedicated inbound
				// limiter on a SEPARATE bucket namespace, so a certificate upload burst and a
				// credential rotation burst cannot mask one another. A private key in transit
				// is more sensitive than a client_secret; the handler returns ONLY public
				// certificate metadata (fingerprint/validity), never the key.
				r.Group(func(r chi.Router) {
					const (
						selfServeCertBurst      = 5          // ≤5 cert uploads in a burst
						selfServeCertRefillPS   = 1.0 / 60.0 // ~1 token/minute sustained
						selfServeCertRetryAfter = 60         // seconds advertised on a 429
					)
					r.Use(newRateLimiter(selfServeCertBurst, selfServeCertRefillPS, nil).middlewareSelfServeCert(selfServeCertRetryAfter))
					r.Put("/bank-certificate", s.handleTenantSetBankCertificate)
				})
			}
		})
	})

	// Admin plane (TB6) — admin auth, segregated from tenant plane. Every route
	// is behind adminAuthMiddleware (deny-by-default; a tenant token never
	// resolves to a role and is rejected). Mutations additionally require the full
	// RoleAdmin; RoleOperator is read-only (least privilege). Read routes that
	// admit operators are added by the admin-UI child guarded by
	// requireRole(RoleAdmin, RoleOperator).
	r.Route("/admin", func(r chi.Router) {
		r.Use(adminAuthMiddleware(s.adminAuth))
		// Defense-in-depth: throttle per authenticated admin identity (falling back
		// to client IP). Sits after auth so invalid tokens are rejected cheaply and
		// each admin identity gets its own bucket, mirroring the tenant plane.
		r.Use(adminLimiter.middleware(adminTokenKey))
		r.Group(func(r chi.Router) {
			r.Use(requireRole(RoleAdmin))
			r.Post("/tenants", s.handleCreateTenant)
			r.Post("/tenants/{tenantID}/pricing", s.handleSetPrice)
			r.Put("/tenants/{tenantID}/bank-credential", s.handleSetBankCredential)
			r.Put("/tenants/{tenantID}/bank-certificate", s.handleSetBankCertificate)
			// Account-key bootstrap (model (b), ADR-0011 §3 / SIN-69280): an admin mints
			// the FIRST bearer key for a named Account — how the board provisions Verz's
			// initial key, then hands it over a secure channel (never a public comment,
			// same discipline as PAYMENT_CONSOLE_BOOTSTRAP_TOKEN). After that the Account
			// self-rotates via POST /v1/account-key. It uses the same create==rotate path
			// (Idempotency-Key required, display-once), and fails closed (503) when the
			// minter is not wired. It is registered unconditionally on the admin plane so
			// the first key can be provisioned before the tenant-facing flag is flipped.
			r.Post("/accounts/{accountID}/account-key", s.handleAdminMintAccountKey)
		})
	})

	// Admin HTML console (SIN-64727) — server-rendered HTMX over the admin plane,
	// built on the merged security spine. Static assets are public (no secrets);
	// every dynamic route is behind admin auth + CSRF (double-submit). Reads admit
	// RoleOperator+RoleAdmin; mutations require the full RoleAdmin (least privilege).
	r.Route("/console", func(r chi.Router) {
		r.Get("/static/*", s.consoleServeStatic)

		// Public self-contained login/bootstrap surface (ADR-0001 Opção B,
		// SIN-69265) — the ONLY authenticated-console exception to deny-by-default.
		// No admin auth (there is no session yet); still hardened: strict security
		// headers, a tight per-IP limiter (anti-brute-force) and CSRF double-submit
		// under the SAME Secure-cookie policy as the session cookie so login itself is
		// not CSRF-forgeable. The double-submit token is seeded on the GET form render
		// and verified on the POST.
		r.Group(func(r chi.Router) {
			r.Use(securityHeaders)
			r.Use(loginLimiter.middleware(func(req *http.Request) string { return "ip:" + clientIP(req) }))
			r.Use(s.csrf.Protect)
			r.Get("/login", s.consoleLoginForm)
			r.Post("/login", s.consoleLogin)
			r.Get("/bootstrap", s.consoleBootstrapForm)
			r.Post("/bootstrap", s.consoleBootstrap)
		})

		r.Group(func(r chi.Router) {
			r.Use(securityHeaders)
			// Accept EITHER the existing admin Bearer (retrocompat, keeps ADR-0001
			// Opção A working) OR a valid first-party session cookie (Opção B).
			// Deny-by-default: neither ⇒ redirect a browser navigation to
			// /console/login, 401 otherwise. The single operator is a full admin
			// (board direction).
			r.Use(s.consoleAuthMiddleware)
			// Defense-in-depth: throttle per authenticated admin identity (IP fallback),
			// mirroring the JSON admin plane. Sits after auth so unauthenticated requests
			// are rejected cheaply, and before CSRF so a token-flood is bounded regardless
			// of whether the double-submit token is present (SIN-64741 L1).
			r.Use(consoleLimiter.middleware(consoleRateKey))
			r.Use(s.csrf.Protect)

			// Logout revokes the current session and clears the cookie (CSRF-guarded);
			// it needs a valid session, so it lives inside the authenticated group.
			r.Post("/logout", s.consoleLogout)

			r.Group(func(r chi.Router) {
				r.Use(requireRole(RoleAdmin, RoleOperator))
				r.Get("/", s.consoleRedirect)
				// Contas (two-level tenancy admin, SIN-69157 / spec SIN-69122). Reads
				// admit Operator+Admin; the account rollup and Faturas never leak another
				// account's tenants (resolved server-side, account-scoped).
				r.Get("/accounts", s.consoleListAccounts)
				r.Get("/accounts/rows", s.consoleAccountRows)
				r.Get("/accounts/new", s.consoleNewAccountForm)
				r.Get("/accounts/{acctId}", s.consoleAccountDetail)
				r.Get("/accounts/{acctId}/tenants/new", s.consoleNewAccountTenantForm)
				r.Get("/accounts/{acctId}/consumption", s.consoleAccountConsumption)
				r.Get("/accounts/{acctId}/consumption/rows", s.consoleAccountConsumptionRows)
				r.Get("/accounts/{acctId}/consumption.csv", s.consoleAccountConsumptionCSV)
				r.Get("/accounts/{acctId}/invoices", s.consoleAccountInvoices)
				// Webhook de saída por Conta (SIN-69490, F0 of SIN-69486), dark behind
				// PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK: the read-only card fragment. Reads admit
				// Operator+Admin; the config is account-scoped (resolved server-side). When
				// the flag is off the route is not registered at all (rollback = config flip).
				if s.accountOutboundWebhook {
					r.Get("/accounts/{acctId}/webhook", s.consoleOutboundWebhookCard)
				}
				r.Get("/tenants", s.consoleListTenants)
				r.Get("/tenants/rows", s.consoleTenantRows)
				r.Get("/tenants/new", s.consoleNewTenantForm)
				r.Get("/tenants/{id}", s.consoleTenantDetail)
				r.Get("/tenants/{id}/credentials", s.consoleCredentialsForm)
				r.Get("/tenants/{id}/banks", s.consoleBankList)
				r.Get("/tenants/{id}/banks/{bankId}", s.consoleBankDetail)
				r.Get("/tenants/{id}/pricing", s.consolePricing)
				r.Get("/tenants/{id}/consumption", s.consoleConsumption)
				r.Get("/tenants/{id}/consumption/rows", s.consoleConsumptionRows)
				r.Get("/tenants/{id}/consumption.csv", s.consoleConsumptionCSV)
				// Faturas (SIN-69121): list + per-invoice CSV download (read side).
				r.Get("/tenants/{id}/invoices", s.consoleInvoices)
				r.Get("/tenants/{id}/invoices/{invId}.csv", s.consoleInvoiceCSV)
			})

			r.Group(func(r chi.Router) {
				r.Use(requireRole(RoleAdmin))
				// Contas mutations (SIN-69157): create/suspend/activate a Conta, create an
				// empresa-cliente already-linked, and batch-generate the account's Faturas.
				// Reassignment of an existing tenant across Contas (C5) is intentionally
				// NOT here — it mutates the tenant on a new axis and is CTO-gated (spec §7).
				r.Post("/accounts", s.consoleCreateAccount)
				r.Post("/accounts/{acctId}/suspend", s.consoleSuspendAccount)
				r.Post("/accounts/{acctId}/activate", s.consoleActivateAccount)
				// Rename a Conta (ADR-0012 §1). PATCH the resource; the domain refuses a
				// derived self-account. CSRF rides the global body hx-headers.
				r.Patch("/accounts/{acctId}", s.consoleRenameAccount)
				r.Post("/accounts/{acctId}/tenants", s.consoleCreateAccountTenant)
				r.Post("/accounts/{acctId}/invoices", s.consoleGenerateAccountInvoices)
				// Generate/rotate a Conta's model (b) account key from the console
				// (SIN-69380). Session + CSRF (this admin mutation group); the browser
				// never touches the Bearer /admin/accounts/{id}/account-key route. Reuses
				// the same accountKeyMint service; returns the plaintext display-once.
				r.Post("/accounts/{acctId}/account-key", s.consoleMintAccountKey)
				// Webhook de saída por Conta mutations (SIN-69490, F0 of SIN-69486), dark
				// behind PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK: set/rotate-secret/remove. Session +
				// CSRF (this admin mutation group); the signing secret is write-only
				// (display-once on set/rotate, never read back). Not registered when off.
				if s.accountOutboundWebhook {
					r.Post("/accounts/{acctId}/webhook", s.consoleSetOutboundWebhook)
					r.Post("/accounts/{acctId}/webhook/secret", s.consoleRotateOutboundWebhookSecret)
					r.Delete("/accounts/{acctId}/webhook", s.consoleRemoveOutboundWebhook)
				}
				r.Post("/tenants", s.consoleCreateTenant)
				r.Post("/tenants/{id}/suspend", s.consoleSuspendTenant)
				r.Post("/tenants/{id}/activate", s.consoleActivateTenant)
				// Rename an empresa-cliente (ADR-0012 §1).
				r.Patch("/tenants/{id}", s.consoleRenameTenant)
				// Remove a tenant's per-bank configuration — hard-delete cred + cert for the
				// (tenant, bank) pair, zeroised before delete and audited (ADR-0012 §5).
				r.Delete("/tenants/{id}/banks/{bankId}", s.consoleRemoveBank)
				r.Post("/tenants/{id}/credentials", s.consoleSetCredential)
				r.Post("/tenants/{id}/banks", s.consoleAddBank)
				r.Post("/tenants/{id}/banks/{bankId}/credential", s.consoleSetBankCredential)
				// Per-bank mTLS certificate upload/rotation (multipart, write-only key;
				// SIN-66088). RBAC + CSRF inherited from this admin mutation group.
				r.Post("/tenants/{id}/banks/{bankId}/certificate", s.consoleSetBankCertificate)
				// Creditor PIX key write — bankless per the binding port-shape decision
				// (SIN-66017 / ADR-0008); writes the tenant's default-bank credential.
				r.Post("/tenants/{id}/creditor-key", s.consoleSetCreditorKey)
				// Fatura generation freezes a consumption window into a durable invoice
				// (append-only). Admin-only write; CSRF inherited from this group.
				r.Post("/tenants/{id}/invoices", s.consoleGenerateInvoice)
				r.Post("/tenants/{id}/pricing", s.consoleSetPrice)
			})
		})
	})

	// C6 bank webhook (TB1→TB5) — authenticity is the opaque per-tenant callback
	// ref in the path (the C6 webhook is unsigned; ADR-0002/F4). The tenant is
	// derived from that authenticated channel in the handler, never from the body.
	// Rate-limited per client IP (defense-in-depth with the body size cap): a
	// flood of guesses against the unguessable URL is throttled regardless of the
	// uniform 401. The ref is a capability secret — see the ingress note below.
	//
	// Ingress: the proxy (SIN-64731) MUST NOT log the full request path for
	// /webhooks/c6/* (the path carries the secret). Mask or drop the path segment
	// in the access log; this app logs only the resolved tenant id, never the ref.
	r.Group(func(r chi.Router) {
		r.Use(webhookLimiter.middleware(func(req *http.Request) string { return "ip:" + clientIP(req) }))
		r.Post("/webhooks/c6/{tenantRef}", s.handleC6Webhook)
	})

	return r
}
