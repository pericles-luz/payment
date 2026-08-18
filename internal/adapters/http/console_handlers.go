package http

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
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
	tv := adminweb.ToTenantView(t)
	s.populateTenantAccount(r.Context(), &tv, t.AccountID())
	s.ui.Page(w, r, "tenant_detail", http.StatusOK, adminweb.DetailView{
		Base:   s.consoleBase(r, t.Name(), "tenants"),
		Tenant: tv,
	})
}

// populateTenantAccount resolves the owning Conta of a tenant into the view so the
// detail can link to it (§5.3). A legacy/self-account tenant (empty or "acct-"
// owner) is left unlinked — the card renders "Conta própria (legado)". A real
// account whose name cannot be resolved falls back to its id (never blank).
func (s *Server) populateTenantAccount(ctx context.Context, tv *adminweb.TenantView, accountID string) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" || account.IsSelfAccountID(accountID) {
		return
	}
	tv.AccountID = accountID
	if a, err := s.console.GetAccount(ctx, accountID); err == nil {
		tv.AccountName = a.Name()
	} else {
		tv.AccountName = accountID
	}
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

// consoleRenameTenant edits a tenant's display name (ADR-0012 §1) from the inline
// rename form. On success it swaps the rename form back with the new value and
// updates the detail header name out-of-band, plus a toast. A validation error
// (blank / too long) re-renders the form inline with the field error (422); a bad
// id yields the same clean 404 as the other routes (no enumeration oracle).
func (s *Server) consoleRenameTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	name := strings.TrimSpace(r.PostFormValue("name"))
	t, err := s.console.RenameTenant(r.Context(), id, name)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrTenantScope) || isServiceError(err) {
			s.consoleError(w, err)
			return
		}
		// Validation error: re-render the rename form with the current name and the
		// inline field error. Re-fetch so the form value reflects the unchanged state.
		cur, gErr := s.console.GetTenant(r.Context(), id)
		if gErr != nil {
			s.consoleError(w, gErr)
			return
		}
		s.ui.Partial(w, http.StatusUnprocessableEntity, "tenant_rename_form",
			adminweb.DetailView{Tenant: adminweb.ToTenantView(cur), Errors: fieldErrors(err, "name")})
		return
	}
	tv := adminweb.ToTenantView(t)
	s.ui.Partials(w, http.StatusOK,
		adminweb.OOBPart{Name: "tenant_rename_form", Data: adminweb.DetailView{Tenant: tv}},
		adminweb.OOBPart{Name: "tenant_name_oob", Data: tv},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "Nome atualizado."}})
}

// consoleRemoveBank hard-deletes a tenant's per-bank configuration — the
// credential and the mTLS certificate for the (tenant, bank) pair (ADR-0012 §5).
// On success it navigates back to the bank list (the bank is gone) with a toast;
// the delete is idempotent, so a repeat is harmless. A bad tenant id / unsupported
// bank slug yields the clean 404 / 400 mapping.
func (s *Server) consoleRemoveBank(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	bankID := chi.URLParam(r, "bankId")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	if err := s.console.RemoveBankConfig(r.Context(), id, bankID); err != nil {
		s.consoleError(w, err)
		return
	}
	view, err := s.bankListView(r, t)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.BodyWithOOB(w, http.StatusOK, "banks", view,
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "Configuração do banco removida."}})
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

// --- Banks (multi-bank console, SIN-66017 / SIN-66086) ---

// consoleBankList renders the tenant's bank list: the configured banks plus the
// closed add-bank selector (supported banks not yet configured). Reads admit
// Operator+Admin (RBAC at the boundary). No secret is ever projected.
func (s *Server) consoleBankList(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view, err := s.bankListView(r, t)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Page(w, r, "banks", http.StatusOK, view)
}

// bankListView assembles the bank list view-model for a tenant (configured banks
// + addable selector), reused by the list render and the add-bank re-render.
func (s *Server) bankListView(r *http.Request, t *tenant.Tenant) (adminweb.BankListView, error) {
	tv := adminweb.ToTenantView(t)
	banks, err := s.console.ListBanks(r.Context(), tv.ID)
	if err != nil {
		return adminweb.BankListView{}, err
	}
	addable, err := s.console.AddableBankSlugs(r.Context(), tv.ID)
	if err != nil {
		return adminweb.BankListView{}, err
	}
	return adminweb.BankListView{
		Base:    s.consoleBase(r, "Bancos", "tenants"),
		Tenant:  tv,
		Banks:   adminweb.ToBankRows(tv.ID, banks, tv.Active),
		Addable: adminweb.ToBankTypeOptions(addable),
		Form:    map[string]string{},
		Errors:  map[string]string{},
	}, nil
}

// consoleAddBank handles the add-bank form. The bank slug is validated against the
// closed allow-list; since there is no per-tenant bank registry, "adding" a bank
// navigates the operator to that bank's detail to configure its credential (the
// bank materialises in the list once a credential is saved). Admin-only.
func (s *Server) consoleAddBank(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	tv := adminweb.ToTenantView(t)
	slug := strings.TrimSpace(r.PostFormValue("bank_type"))
	info, err := s.console.GetBank(r.Context(), tv.ID, slug)
	if err != nil {
		// Unknown/unsupported slug (closed selector backstop): re-render the list
		// with an inline error; never echo an unsupported value into a row.
		view, vErr := s.bankListView(r, t)
		if vErr != nil {
			s.consoleError(w, vErr)
			return
		}
		view.Errors = map[string]string{"bank_type": "banco não suportado"}
		s.ui.Page(w, r, "banks", http.StatusUnprocessableEntity, view)
		return
	}
	// Navigate to the bank detail to configure the credential, with a toast.
	s.ui.BodyWithOOB(w, http.StatusOK, "bank_detail",
		adminweb.BankDetailView{
			Base:   s.consoleBase(r, info.Slug, "tenants"),
			Tenant: tv,
			Bank:   adminweb.ToBankRows(tv.ID, []app.BankInfo{info}, tv.Active)[0],
			Form:   map[string]string{},
			Errors: map[string]string{},
		},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "Banco adicionado. Configure a credencial para ativá-lo."}})
}

// consoleBankDetail renders one bank's detail (credential + creditor-key cards).
// An unknown bank slug 404s (deny-by-default). Reads admit Operator+Admin.
func (s *Server) consoleBankDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	bankID := chi.URLParam(r, "bankId")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	tv := adminweb.ToTenantView(t)
	info, err := s.console.GetBank(r.Context(), tv.ID, bankID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Page(w, r, "bank_detail", http.StatusOK, adminweb.BankDetailView{
		Base:             s.consoleBase(r, info.Slug, "tenants"),
		Tenant:           tv,
		Bank:             adminweb.ToBankRows(tv.ID, []app.BankInfo{info}, tv.Active)[0],
		Form:             map[string]string{},
		Errors:           map[string]string{},
		CreditorEditable: info.Slug == ports.BankIDC6,
	})
}

// consoleSetCreditorKey records the tenant's PIX creditor key (chave do
// recebedor) and replies with a card-only HTMX swap (hx-target=#creditor-card):
// only the creditor card re-renders. The write targets the tenant's default-bank
// credential (BankIDC6) — the binding bankless write path (SIN-66017 / ADR-0008);
// the card is rendered editable only on that bank's detail page. RBAC (RoleAdmin)
// and CSRF are inherited from the console mutation group — not re-implemented. The
// key is routing-sensitive and never echoed back into the form.
func (s *Server) consoleSetCreditorKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	tv := adminweb.ToTenantView(t)
	card := func(status int, info app.BankInfo, errs map[string]string, saved bool) {
		s.ui.Partial(w, status, "creditor_card", adminweb.BankDetailView{
			Base:             s.consoleBase(r, info.Slug, "tenants"),
			Tenant:           tv,
			Bank:             adminweb.ToBankRows(tv.ID, []app.BankInfo{info}, tv.Active)[0],
			Form:             map[string]string{},
			Errors:           errs,
			CreditorSaved:    saved,
			CreditorEditable: true,
		})
	}
	key := strings.TrimSpace(r.PostFormValue("creditor_key"))
	if err := s.console.SetCreditorKey(r.Context(), tv.ID, key); err != nil {
		// Re-read so the card reflects current state; never echo the key value.
		info, gerr := s.console.GetBank(r.Context(), tv.ID, ports.BankIDC6)
		if gerr != nil {
			s.consoleError(w, gerr)
			return
		}
		card(http.StatusUnprocessableEntity, info, creditorErrors(err), false)
		return
	}
	// Setting the PIX key is the operator-plane half of the cred+key pair (the
	// self-serve credential is the tenant-plane half). Completing it here may be what
	// finally lets the client be registered with C6 — attempt the in-flow registration
	// (SIN-69560 / F2). Best-effort: TryRegister never errors, so the card still renders
	// its success state regardless of the PSP outcome; unwired (nil) is a no-op.
	if s.webhookReg != nil {
		s.webhookReg.TryRegister(r.Context(), tv.ID)
	}
	info, err := s.console.GetBank(r.Context(), tv.ID, ports.BankIDC6)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	card(http.StatusOK, info, map[string]string{}, true)
}

// creditorErrors maps a creditor-key write failure to the card's inline errors,
// never leaking the key. A missing bank credential (ErrNotFound) is a
// user-actionable precondition — a creditor key needs a bank identity first — so
// it surfaces as a form banner rather than 404-ing the card; an invalid key shape
// surfaces inline on the field.
func creditorErrors(err error) map[string]string {
	if errors.Is(err, shared.ErrNotFound) {
		return map[string]string{"form": "configure a credencial bancária do tenant antes de definir a chave do recebedor"}
	}
	return fieldErrors(err, "creditor_key")
}

// consoleSetBankCredential writes a tenant's credential for a specific bank and
// swaps only the credential card back (outerHTML #cred-card). The secret is never
// echoed; only the non-secret client_id is re-shown on a validation error.
// Admin-only.
func (s *Server) consoleSetBankCredential(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	bankID := chi.URLParam(r, "bankId")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	tv := adminweb.ToTenantView(t)
	// Validate the bank slug up front so an unknown bank 404s rather than rendering
	// a card for a bank that can never route a charge.
	if _, err := s.console.GetBank(r.Context(), tv.ID, bankID); err != nil {
		s.consoleError(w, err)
		return
	}
	clientID := strings.TrimSpace(r.PostFormValue("client_id"))
	secret := r.PostFormValue("secret")
	card := func(status int, info app.BankInfo, form, errs map[string]string, saved bool) {
		s.ui.Partial(w, status, "cred_card", adminweb.BankDetailView{
			Base:      s.consoleBase(r, info.Slug, "tenants"),
			Tenant:    tv,
			Bank:      adminweb.ToBankRows(tv.ID, []app.BankInfo{info}, tv.Active)[0],
			Form:      form,
			Errors:    errs,
			CredSaved: saved,
		})
	}
	if err := s.console.SetBankCredentialFor(r.Context(), tv.ID, bankID, clientID, secret); err != nil {
		// Re-read so the card reflects the current (pre-write) state; echo only client_id.
		info, _ := s.console.GetBank(r.Context(), tv.ID, bankID)
		card(http.StatusUnprocessableEntity, info, map[string]string{"client_id": clientID}, fieldErrors(err, "client_id", "secret", "bank"), false)
		return
	}
	info, err := s.console.GetBank(r.Context(), tv.ID, bankID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	card(http.StatusOK, info, map[string]string{}, map[string]string{}, true)
}

// --- Bank mTLS certificate (write-only key) ---

// maxCertUploadBytes caps the multipart certificate upload. A PEM cert + key pair
// is a few KiB; 256 KiB is generous while bounding memory from an oversize upload
// (threat H3). Exceeding it yields a 413 with an inline message, not a 500.
const maxCertUploadBytes = 256 << 10

// consoleSetBankCertificate handles the per-bank mTLS certificate upload/rotation
// (SIN-66088). It is a multipart form (two PEM file fields, cert_pem + key_pem) and
// swaps only the certificate card back (outerHTML #cert-card) plus an out-of-band
// refresh of the detail header badge and a toast. The private key is write-only:
// it is uploaded, validated + key-matched server-side, stored in the vault, and
// NEVER echoed, logged or re-rendered (threat C1/C4). RBAC (RoleAdmin) and CSRF are
// inherited from the console mutation group. Admin-only.
func (s *Server) consoleSetBankCertificate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	bankID := chi.URLParam(r, "bankId")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	tv := adminweb.ToTenantView(t)
	// Validate the bank slug up front so an unknown bank 404s rather than rendering
	// a card for a bank that can never present a client certificate.
	if _, err := s.console.GetBank(r.Context(), tv.ID, bankID); err != nil {
		s.consoleError(w, err)
		return
	}

	// reread re-projects the bank so the card reflects current state (the existing
	// certificate, if any) on every render — success or error.
	reread := func() app.BankInfo {
		info, _ := s.console.GetBank(r.Context(), tv.ID, bankID)
		return info
	}
	card := func(status int, info app.BankInfo, errs map[string]string) {
		s.ui.Partial(w, status, "cert_card", adminweb.BankDetailView{
			Base:   s.consoleBase(r, info.Slug, "tenants"),
			Tenant: tv,
			Bank:   adminweb.ToBankRows(tv.ID, []app.BankInfo{info}, tv.Active)[0],
			Form:   map[string]string{},
			Errors: errs,
		})
	}

	// Bound the upload and parse the multipart body. An oversize body surfaces as a
	// 413 with an inline message; any other parse failure is a generic 400-class
	// inline error (never a 500).
	r.Body = http.MaxBytesReader(w, r.Body, maxCertUploadBytes)
	if err := r.ParseMultipartForm(maxCertUploadBytes); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			card(http.StatusRequestEntityTooLarge, reread(), map[string]string{"form": "arquivo muito grande (máx. 256 KiB)"})
			return
		}
		card(http.StatusBadRequest, reread(), map[string]string{"form": "envio inválido"})
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	certPEM, certOK := readUploadField(r, "cert_pem")
	keyPEM, keyOK := readUploadField(r, "key_pem")
	if !certOK || strings.TrimSpace(certPEM) == "" {
		card(http.StatusUnprocessableEntity, reread(), map[string]string{"cert_pem": "selecione o arquivo do certificado (PEM)"})
		return
	}
	if !keyOK || strings.TrimSpace(keyPEM) == "" {
		card(http.StatusUnprocessableEntity, reread(), map[string]string{"key_pem": "selecione o arquivo da chave privada (PEM)"})
		return
	}

	if _, err := s.console.SetBankCertificate(r.Context(), tv.ID, bankID, certPEM, keyPEM); err != nil {
		// Map the named validation error to the field it concerns; never echo the key.
		card(http.StatusUnprocessableEntity, reread(), fieldErrors(err, "cert_pem", "key_pem"))
		return
	}
	// Success: swap the card (now showing the new metadata), refresh the header
	// badge out-of-band, and toast. The key never appears in any of these.
	info := reread()
	row := adminweb.ToBankRows(tv.ID, []app.BankInfo{info}, tv.Active)[0]
	s.ui.Partials(w, http.StatusOK,
		adminweb.OOBPart{Name: "cert_card", Data: adminweb.BankDetailView{
			Base:      s.consoleBase(r, info.Slug, "tenants"),
			Tenant:    tv,
			Bank:      row,
			Form:      map[string]string{},
			Errors:    map[string]string{},
			CertSaved: true,
		}},
		adminweb.OOBPart{Name: "cert_status_oob", Data: row},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "Certificado salvo."}})
}

// readUploadField reads an uploaded PEM file field into a string, bounded by the
// upload cap. A missing field returns ("", false) so the handler can render a
// precise inline error. The key never transits any log on this path.
func readUploadField(r *http.Request, field string) (string, bool) {
	f, _, err := r.FormFile(field)
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxCertUploadBytes))
	if err != nil {
		return "", false
	}
	return string(b), true
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

// consumptionDateLayout is the ISO date form the <input type="date"> controls and
// the CSV link speak (YYYY-MM-DD).
const consumptionDateLayout = "2006-01-02"

// parseConsumptionRange reads the start_date/end_date query params, defaulting to
// the last 30 days when absent. The returned strings echo the effective window
// back into the form and CSV link. The range is half-open [start, end+1day) so
// the end date is inclusive of its whole day. A malformed date yields
// ErrValidation (mapped to 400 at the boundary), never a silent default.
func parseConsumptionRange(r *http.Request, now time.Time) (app.ConsumptionRange, string, string, error) {
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start, end := today.AddDate(0, 0, -30), today
	q := r.URL.Query()
	if v := strings.TrimSpace(q.Get("start_date")); v != "" {
		p, err := time.ParseInLocation(consumptionDateLayout, v, time.UTC)
		if err != nil {
			return app.ConsumptionRange{}, "", "", shared.NewValidationError("start_date", "data inicial inválida")
		}
		start = p
	}
	if v := strings.TrimSpace(q.Get("end_date")); v != "" {
		p, err := time.ParseInLocation(consumptionDateLayout, v, time.UTC)
		if err != nil {
			return app.ConsumptionRange{}, "", "", shared.NewValidationError("end_date", "data final inválida")
		}
		end = p
	}
	rng := app.ConsumptionRange{Start: start, End: end.AddDate(0, 0, 1)}
	return rng, start.Format(consumptionDateLayout), end.Format(consumptionDateLayout), nil
}

func (s *Server) consoleConsumption(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	rng, startStr, endStr, err := parseConsumptionRange(r, s.console.Now())
	if err != nil {
		s.consoleError(w, err)
		return
	}
	rep, err := s.console.ConsumptionInRange(r.Context(), id, rng)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view := adminweb.ToConsumptionView(adminweb.ToTenantView(t), rep)
	view.StartDate, view.EndDate = startStr, endStr
	view.Base = s.consoleBase(r, "Consumo", "tenants")
	s.ui.Page(w, r, "consumption", http.StatusOK, view)
}

// consoleConsumptionRows renders just the consumption table for a date-range
// filter swap (hx-target="#consumption-rows"), mirroring consoleTenantRows. The
// tenant is resolved by ConsumptionInRange, so an unknown id still 404s cleanly.
func (s *Server) consoleConsumptionRows(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	rng, startStr, endStr, err := parseConsumptionRange(r, s.console.Now())
	if err != nil {
		s.consoleError(w, err)
		return
	}
	rep, err := s.console.ConsumptionInRange(r.Context(), id, rng)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view := adminweb.ToConsumptionView(adminweb.ToTenantView(t), rep)
	view.StartDate, view.EndDate = startStr, endStr
	s.ui.Partial(w, http.StatusOK, "consumption_rows", view)
}

// consoleConsumptionCSV exports the per-endpoint consumption for the active
// window as a CSV download. It is a read-only, same-origin GET (CSP-friendly);
// money is emitted in both integer centavos (exact) and a locale-neutral decimal.
func (s *Server) consoleConsumptionCSV(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rng, startStr, endStr, err := parseConsumptionRange(r, s.console.Now())
	if err != nil {
		s.consoleError(w, err)
		return
	}
	rep, err := s.console.ConsumptionInRange(r.Context(), id, rng)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// startStr/endStr are validated YYYY-MM-DD, so the filename carries no
	// user-controlled bytes (no header-injection surface).
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"consumo-%s-a-%s.csv\"", startStr, endStr))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"endpoint", "chamadas", "total_centavos", "total_reais"})
	for _, l := range rep.Lines {
		_ = cw.Write([]string{csvSafe(l.Endpoint), strconv.Itoa(l.Calls), strconv.FormatInt(l.TotalCents, 10), centsDecimal(l.TotalCents)})
	}
	_ = cw.Write([]string{"TOTAL", strconv.Itoa(rep.TotalCalls), strconv.FormatInt(rep.TotalCents, 10), centsDecimal(rep.TotalCents)})
	cw.Flush()
}

// csvSafe neutraliza CSV formula injection (CWE-1236): encoding/csv só escapa a
// estrutura CSV (vírgula/aspas/quebra de linha), não neutraliza fórmula. Uma
// célula começando com '=', '+', '-', '@', TAB (0x09) ou CR (0x0D) é interpretada
// como fórmula por Excel/LibreOffice/Sheets. Prefixamos essas células de texto-livre
// com uma aspa simples (padrão OWASP); a aspa fica visível na célula (risco residual
// aceito). Colunas numéricas (strconv/centsDecimal) não passam por aqui.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', 0x09, 0x0D:
		return "'" + s
	}
	return s
}

// centsDecimal renders integer centavos as a locale-neutral decimal string
// (e.g. 250 -> "2.50") suitable for spreadsheet import.
func centsDecimal(cents int64) string {
	neg := ""
	if cents < 0 {
		neg, cents = "-", -cents
	}
	return fmt.Sprintf("%s%d.%02d", neg, cents/100, cents%100)
}

// --- Invoices (Faturas, SIN-69121) ---

// consoleInvoices renders the "Faturas" screen: the tenant's generated invoices
// (newest-first) plus the period picker that drives generation. The date inputs
// default to the last 30 days (parseConsumptionRange), so the reseller has a
// sensible pre-filled window without typing.
func (s *Server) consoleInvoices(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	_, startStr, endStr, err := parseConsumptionRange(r, s.console.Now())
	if err != nil {
		s.consoleError(w, err)
		return
	}
	invs, err := s.console.ListInvoices(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view := adminweb.ToInvoicesView(adminweb.ToTenantView(t), invs)
	view.StartDate, view.EndDate = startStr, endStr
	view.Base = s.consoleBase(r, "Faturas", "tenants")
	s.ui.Page(w, r, "invoices", http.StatusOK, view)
}

// consoleGenerateInvoice generates (freezes) an invoice for a bounded period and
// re-renders the Faturas list with a success toast. The period comes from the
// POST body (RoleAdmin + CSRF inherited from the mutation group); an unbounded or
// malformed window is a 400 via the domain validation error.
func (s *Server) consoleGenerateInvoice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	t, err := s.console.GetTenant(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	rng, startStr, endStr, err := parseInvoicePeriod(r)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	if _, err := s.console.GenerateInvoice(r.Context(), id, rng); err != nil {
		s.consoleError(w, err)
		return
	}
	invs, err := s.console.ListInvoices(r.Context(), id)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view := adminweb.ToInvoicesView(adminweb.ToTenantView(t), invs)
	view.StartDate, view.EndDate = startStr, endStr
	view.Base = s.consoleBase(r, "Faturas", "tenants")
	s.ui.BodyWithOOB(w, http.StatusOK, "invoices", view,
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "Fatura gerada."}})
}

// consoleInvoiceCSV downloads one invoice as a CSV document. Read-only, same-
// origin GET (CSP-friendly). Money is emitted in both integer centavos (exact)
// and a locale-neutral decimal. The filename is built from the invoice's own
// server-side period (never the raw URL id), so it carries no header-injection
// surface.
func (s *Server) consoleInvoiceCSV(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	invID := chi.URLParam(r, "invId")
	inv, err := s.console.GetInvoice(r.Context(), id, invID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	from := inv.PeriodStart().UTC().Format(consumptionDateLayout)
	to := inv.PeriodEnd().UTC().AddDate(0, 0, -1).Format(consumptionDateLayout)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"fatura-%s-a-%s.csv\"", from, to))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"endpoint", "chamadas", "total_centavos", "total_reais"})
	for _, l := range inv.Lines() {
		_ = cw.Write([]string{csvSafe(l.Endpoint()), strconv.Itoa(l.Calls()), strconv.FormatInt(l.SubtotalCents(), 10), centsDecimal(l.SubtotalCents())})
	}
	_ = cw.Write([]string{"TOTAL", strconv.Itoa(inv.TotalCalls()), strconv.FormatInt(inv.TotalCents(), 10), centsDecimal(inv.TotalCents())})
	cw.Flush()
}

// parseInvoicePeriod reads the required start_date/end_date from the POST body
// and returns a BOUNDED half-open window [start, end+1day). Both dates are
// required (an invoice bills a definite period); a missing or malformed value is
// a validation error surfaced as 400. The echoed strings refill the picker.
func parseInvoicePeriod(r *http.Request) (app.ConsumptionRange, string, string, error) {
	startRaw := strings.TrimSpace(r.PostFormValue("start_date"))
	endRaw := strings.TrimSpace(r.PostFormValue("end_date"))
	if startRaw == "" || endRaw == "" {
		return app.ConsumptionRange{}, "", "", shared.NewValidationError("period", "período inicial e final são obrigatórios")
	}
	start, err := time.ParseInLocation(consumptionDateLayout, startRaw, time.UTC)
	if err != nil {
		return app.ConsumptionRange{}, "", "", shared.NewValidationError("start_date", "data inicial inválida")
	}
	end, err := time.ParseInLocation(consumptionDateLayout, endRaw, time.UTC)
	if err != nil {
		return app.ConsumptionRange{}, "", "", shared.NewValidationError("end_date", "data final inválida")
	}
	// Half-open [start, end+1day) so the chosen end day is inclusive of its charges.
	rng := app.ConsumptionRange{Start: start, End: end.AddDate(0, 0, 1)}
	return rng, start.Format(consumptionDateLayout), end.Format(consumptionDateLayout), nil
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
	case errors.Is(err, app.ErrInvoicesUnavailable), errors.Is(err, app.ErrAccountsUnavailable),
		errors.Is(err, app.ErrOutboundWebhookUnavailable):
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
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
