package http

import (
	"context"
	"errors"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

// console_handlers.go is the server-rendered HTMX admin console (SIN-64727). It
// renders adminweb templates over the app.ConsoleService use-cases. Security is
// inherited from the merged spine (SIN-64726): every console route is behind
// adminAuthMiddleware (deny-by-default), reads admit RoleOperator+RoleAdmin while
// mutations require RoleAdmin (least privilege), and CSRFProtect double-submit
// guards every browser POST. Output is auto-escaped by html/template (XSS-safe)
// and no secret is ever rendered.

// consoleBase builds the layout fields for a full page render: the per-request
// CSRF token (echoed into forms / hx-headers) and the operator's display label
// derived server-side from the authenticated role.
func (s *Server) consoleBase(r *http.Request, title, nav string) adminweb.Base {
	role, _ := roleFromContext(r.Context())
	label := "operador · " + string(role)
	return adminweb.NewBase(title, nav, CSRFToken(r.Context()), label)
}

func (s *Server) consoleRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/console/tenants", http.StatusSeeOther)
}

// securityHeaders applies a strict, self-only baseline to the HTML console. The
// CSP forbids inline script/style (htmx is self-hosted; styles are in app.css),
// blocks framing/clickjacking and constrains form submission to same-origin —
// defense-in-depth alongside the double-submit CSRF check (threat: XSS/UI-redress).
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
		"connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) consoleServeStatic(w http.ResponseWriter, r *http.Request) {
	name := path.Base(path.Clean("/" + chi.URLParam(r, "*")))
	s.ui.ServeStatic(w, name)
}

// --- Tenant list ---

func (s *Server) consoleListTenants(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	status := app.ParseStatusFilter(r.URL.Query().Get("status"))
	tenants, err := s.console.ListTenants(r.Context(), app.ListTenantsQuery{Search: search, Status: status})
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Page(w, r, "tenants_list", http.StatusOK, adminweb.ListView{
		Base:    s.consoleBase(r, "Tenants", "tenants"),
		Tenants: adminweb.ToTenantViews(tenants),
		Search:  search,
		Status:  string(status),
	})
}

func (s *Server) consoleTenantRows(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	status := app.ParseStatusFilter(r.URL.Query().Get("status"))
	tenants, err := s.console.ListTenants(r.Context(), app.ListTenantsQuery{Search: search, Status: status})
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Partial(w, http.StatusOK, "tenant_rows", adminweb.RowsView{
		Tenants: adminweb.ToTenantViews(tenants),
		Search:  search,
	})
}

// --- Create tenant ---

func (s *Server) consoleNewTenantForm(w http.ResponseWriter, r *http.Request) {
	s.ui.Page(w, r, "tenant_new", http.StatusOK, adminweb.NewTenantView{
		Base:   s.consoleBase(r, "Novo tenant", "tenants"),
		Form:   map[string]string{},
		Errors: map[string]string{},
	})
}

func (s *Server) consoleCreateTenant(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	t, err := s.console.CreateTenant(r.Context(), name)
	if err != nil {
		s.ui.Page(w, r, "tenant_new", http.StatusUnprocessableEntity, adminweb.NewTenantView{
			Base:   s.consoleBase(r, "Novo tenant", "tenants"),
			Form:   map[string]string{"name": name},
			Errors: fieldErrors(err, "name"),
		})
		return
	}
	tv := adminweb.ToTenantView(t)
	s.ui.BodyWithOOB(w, http.StatusOK, "tenant_detail",
		adminweb.DetailView{Base: s.consoleBase(r, t.Name(), "tenants"), Tenant: tv},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "Tenant criado."}})
}

// --- Tenant detail + lifecycle ---

func (s *Server) consoleTenantDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Page(w, r, "tenant_detail", http.StatusOK, adminweb.DetailView{
		Base:   s.consoleBase(r, t.Name(), "tenants"),
		Tenant: adminweb.ToTenantView(t),
	})
}

func (s *Server) consoleSuspendTenant(w http.ResponseWriter, r *http.Request) {
	s.consoleTransition(w, r, s.console.SuspendTenant, "Tenant suspenso.")
}

func (s *Server) consoleActivateTenant(w http.ResponseWriter, r *http.Request) {
	s.consoleTransition(w, r, s.console.ActivateTenant, "Tenant reativado.")
}

// consoleTransition runs a tenant lifecycle change (suspend/activate) and
// replies with pure out-of-band swaps (hx-swap="none"): the status badge + the
// toggle button update in place, plus a toast — no full-screen re-render.
func (s *Server) consoleTransition(w http.ResponseWriter, r *http.Request, op func(context.Context, string) (*tenant.Tenant, error), msg string) {
	id := chi.URLParam(r, "id")
	t, err := op(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	tv := adminweb.ToTenantView(t)
	s.ui.Partials(w, http.StatusOK,
		adminweb.OOBPart{Name: "status_header_oob", Data: tv},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: msg}})
}

// --- Bank credentials (write-only) ---

func (s *Server) consoleCredentialsForm(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Page(w, r, "credentials", http.StatusOK, adminweb.CredentialView{
		Base:   s.consoleBase(r, "Credenciais", "tenants"),
		Tenant: adminweb.ToTenantView(t),
		Form:   map[string]string{},
		Errors: map[string]string{},
	})
}

func (s *Server) consoleSetCredential(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	tv := adminweb.ToTenantView(t)
	clientID := strings.TrimSpace(r.PostFormValue("client_id"))
	secret := r.PostFormValue("secret")
	if err := s.console.SetBankCredential(r.Context(), id, clientID, secret); err != nil {
		// Echo only the non-secret client_id back; never the secret.
		s.ui.Page(w, r, "credentials", http.StatusUnprocessableEntity, adminweb.CredentialView{
			Base:   s.consoleBase(r, "Credenciais", "tenants"),
			Tenant: tv,
			Form:   map[string]string{"client_id": clientID},
			Errors: fieldErrors(err, "client_id", "secret"),
		})
		return
	}
	s.ui.Page(w, r, "credentials", http.StatusOK, adminweb.CredentialView{
		Base:   s.consoleBase(r, "Credenciais", "tenants"),
		Tenant: tv,
		Form:   map[string]string{},
		Errors: map[string]string{},
		Saved:  true,
	})
}

// --- Pricing ---

func (s *Server) consolePricing(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	prices, err := s.console.ListPricing(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Page(w, r, "pricing", http.StatusOK, adminweb.PricingView{
		Base:   s.consoleBase(r, "Tarifação", "tenants"),
		Tenant: adminweb.ToTenantView(t),
		Prices: adminweb.ToPriceRows(prices),
		Form:   map[string]string{},
		Errors: map[string]string{},
	})
}

func (s *Server) consoleSetPrice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	tv := adminweb.ToTenantView(t)
	endpoint := strings.TrimSpace(r.PostFormValue("endpoint"))
	priceRaw := strings.TrimSpace(r.PostFormValue("price_cents"))
	render := func(status int, formErrors map[string]string) {
		prices, listErr := s.console.ListPricing(r.Context(), id)
		if listErr != nil {
			s.consoleError(w, listErr)
			return
		}
		s.ui.Page(w, r, "pricing", status, adminweb.PricingView{
			Base:   s.consoleBase(r, "Tarifação", "tenants"),
			Tenant: tv,
			Prices: adminweb.ToPriceRows(prices),
			Form:   map[string]string{"endpoint": endpoint, "price_cents": priceRaw},
			Errors: formErrors,
		})
	}
	cents, convErr := strconv.ParseInt(priceRaw, 10, 64)
	if convErr != nil || cents < 0 {
		render(http.StatusUnprocessableEntity, map[string]string{"price_cents": "informe um valor inteiro em centavos (≥ 0)"})
		return
	}
	if _, err := s.console.SetPrice(r.Context(), id, endpoint, cents); err != nil {
		render(http.StatusUnprocessableEntity, fieldErrors(err, "endpoint", "price_cents"))
		return
	}
	render(http.StatusOK, map[string]string{})
}

// --- Consumption audit (read-only) ---

func (s *Server) consoleConsumption(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	rep, err := s.console.Consumption(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view := adminweb.ToConsumptionView(adminweb.ToTenantView(t), rep)
	view.Base = s.consoleBase(r, "Consumo", "tenants")
	s.ui.Page(w, r, "consumption", http.StatusOK, view)
}

// --- helpers ---

// consoleError maps a use-case error to an HTML error response, mirroring the
// JSON plane's mapping but never leaking internal detail.
func (s *Server) consoleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound), errors.Is(err, shared.ErrTenantScope):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, shared.ErrValidation):
		http.Error(w, "invalid request", http.StatusBadRequest)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// fieldErrors maps a domain validation error to the field it concerns so the
// form can render it inline. A *shared.ValidationError names its field; a known
// field is surfaced inline, an unknown field (or a non-validation error) falls
// back to a generic "form" banner so the boundary never leaks internal detail.
func fieldErrors(err error, known ...string) map[string]string {
	out := map[string]string{}
	var ve *shared.ValidationError
	if errors.As(err, &ve) {
		for _, k := range known {
			if ve.Field == k {
				out[k] = ve.Msg
				return out
			}
		}
		out["form"] = ve.Msg
		return out
	}
	if errors.Is(err, shared.ErrValidation) {
		out["form"] = "dados inválidos"
		return out
	}
	out["form"] = "não foi possível concluir a operação"
	return out
}
