package http

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
)

// Server holds the application services and authenticators behind the HTTP
// driving adapter. It is constructed once at startup and is safe for concurrent
// use.
type Server struct {
	charges     *app.ChargeService
	admin       *app.AdminService
	console     *app.ConsoleService
	ui          *adminweb.Renderer
	webhooks    *app.WebhookService
	tenantAuth  TenantAuthenticator
	adminAuth   AdminPrincipalAuthenticator
	webhookAuth WebhookAuthenticator
	csrf        CSRFGuard
}

// Config wires a Server's dependencies. Console and UI back the HTML admin
// console (SIN-64727); they may be nil for deployments/tests that serve only the
// JSON planes — the console routes are then registered but never exercised.
type Config struct {
	Charges     *app.ChargeService
	Admin       *app.AdminService
	Console     *app.ConsoleService
	UI          *adminweb.Renderer
	Webhooks    *app.WebhookService
	TenantAuth  TenantAuthenticator
	AdminAuth   AdminPrincipalAuthenticator
	WebhookAuth WebhookAuthenticator
	// SecureCookies sets the Secure attribute on cookies this adapter issues
	// (CSRF token; the admin-UI session cookie via Server.CSRF). Driven by config
	// because TLS is terminated at a proxy — see config.Config.SecureCookies.
	SecureCookies bool
}

// NewServer builds a Server from its config.
func NewServer(c Config) *Server {
	return &Server{
		charges:     c.Charges,
		admin:       c.Admin,
		console:     c.Console,
		ui:          c.UI,
		webhooks:    c.Webhooks,
		tenantAuth:  c.TenantAuth,
		adminAuth:   c.AdminAuth,
		webhookAuth: c.WebhookAuth,
		csrf:        NewCSRFGuard(c.SecureCookies),
	}
}

// CSRF returns the server's CSRF guard so the admin-UI child can wrap its live
// HTML routes with Protect under the configured Secure-cookie policy.
func (s *Server) CSRF() CSRFGuard { return s.csrf }

// Router builds the HTTP handler. All routes are authenticated (deny-by-default);
// the public health check is the only unauthenticated route.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
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

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Tenant API (TB1) — authenticated, tenant-scoped, rate-limited.
	r.Route("/v1", func(r chi.Router) {
		r.Use(tenantAuthMiddleware(s.tenantAuth))
		r.Use(tenantLimiter.middleware(tenantOrIPKey))
		r.Post("/charges", s.handleCreateCharge)
		r.Get("/charges/{id}", s.handleGetCharge)
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
				r.Get("/tenants", s.consoleListTenants)
				r.Get("/tenants/rows", s.consoleTenantRows)
				r.Get("/tenants/new", s.consoleNewTenantForm)
				r.Get("/tenants/{id}", s.consoleTenantDetail)
				r.Get("/tenants/{id}/credentials", s.consoleCredentialsForm)
				r.Get("/tenants/{id}/pricing", s.consolePricing)
				r.Get("/tenants/{id}/consumption", s.consoleConsumption)
			})

			r.Group(func(r chi.Router) {
				r.Use(requireRole(RoleAdmin))
				r.Post("/tenants", s.consoleCreateTenant)
				r.Post("/tenants/{id}/suspend", s.consoleSuspendTenant)
				r.Post("/tenants/{id}/activate", s.consoleActivateTenant)
				r.Post("/tenants/{id}/credentials", s.consoleSetCredential)
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
