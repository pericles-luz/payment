package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/version"
)

// Server holds the application services and authenticators behind the HTTP
// driving adapter. It is constructed once at startup and is safe for concurrent
// use.
type Server struct {
	charges     *app.ChargeService
	pix         *app.PixService
	pixCobV     *app.PixDueChargeService
	checkout    *app.CheckoutService
	boleto      *app.BoletoService
	dda         *app.DDAService
	statement   *app.StatementService
	admin       *app.AdminService
	console     *app.ConsoleService
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
	Statement   *app.StatementService
	Admin       *app.AdminService
	Console     *app.ConsoleService
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
}

// NewServer builds a Server from its config.
func NewServer(c Config) *Server {
	return &Server{
		charges:             c.Charges,
		pix:                 c.Pix,
		pixCobV:             c.PixCobV,
		checkout:            c.Checkout,
		boleto:              c.Boleto,
		dda:                 c.DDA,
		statement:           c.Statement,
		admin:               c.Admin,
		console:             c.Console,
		ui:                  c.UI,
		webhooks:            c.Webhooks,
		tenantAuth:          c.TenantAuth,
		adminAuth:           c.AdminAuth,
		webhookAuth:         c.WebhookAuth,
		accountResolver:     c.AccountResolver,
		csrf:                NewCSRFGuard(c.SecureCookies),
		bankResolver:        c.BankResolver,
		trustedProxyHops:    c.TrustedProxyHops,
		selfServeCredIntake: c.SelfServeCredIntake,
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
		r.Use(tenantAuthMiddleware(s.tenantAuth, s.accountResolver))
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
			})
		}
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
		})
	})

	// Admin HTML console (SIN-64727) — server-rendered HTMX over the admin plane,
	// built on the merged security spine. Static assets are public (no secrets);
	// every dynamic route is behind admin auth + CSRF (double-submit). Reads admit
	// RoleOperator+RoleAdmin; mutations require the full RoleAdmin (least privilege).
	r.Route("/console", func(r chi.Router) {
		r.Get("/static/*", s.consoleServeStatic)
		r.Group(func(r chi.Router) {
			r.Use(securityHeaders)
			r.Use(adminAuthMiddleware(s.adminAuth))
			// Defense-in-depth: throttle per authenticated admin identity (IP fallback),
			// mirroring the JSON admin plane. Sits after auth so unauthenticated requests
			// are rejected cheaply, and before CSRF so a token-flood is bounded regardless
			// of whether the double-submit token is present (SIN-64741 L1).
			r.Use(consoleLimiter.middleware(adminTokenKey))
			r.Use(CSRFProtect)

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
				r.Post("/accounts/{acctId}/tenants", s.consoleCreateAccountTenant)
				r.Post("/accounts/{acctId}/invoices", s.consoleGenerateAccountInvoices)
				r.Post("/tenants", s.consoleCreateTenant)
				r.Post("/tenants/{id}/suspend", s.consoleSuspendTenant)
				r.Post("/tenants/{id}/activate", s.consoleActivateTenant)
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
