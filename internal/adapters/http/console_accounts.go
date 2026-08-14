package http

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
)

// isServiceError reports whether err is a "dependency not configured" service
// error (accounts/invoices store absent) that must map to 503 at the boundary,
// rather than a validation error rendered inline on a form.
func isServiceError(err error) bool {
	return errors.Is(err, app.ErrAccountsUnavailable) || errors.Is(err, app.ErrInvoicesUnavailable)
}

// console_accounts.go is the server-rendered HTMX console for the two-level
// tenancy admin plane (SIN-69157, spec SIN-69122): the Contas CRUD, the
// empresas-clientes nested under a Conta (create-already-linked), the
// account→tenant usage rollup and the account-scoped Faturas. Every route joins the
// existing /console group, so it inherits deny-by-default admin auth, CSRF and the
// per-admin rate limit — nothing here re-implements security. Output is auto-escaped
// by html/template. No secret is rendered (an account carries none by construction).

// --- Contas list + create ---

// parseIncludeSelf reads the "show self-accounts" toggle. Off by default so the
// Contas list is not polluted by the per-tenant legacy self-accounts (spec §6).
func parseIncludeSelf(r *http.Request) bool {
	v := strings.TrimSpace(r.URL.Query().Get("show_self"))
	return v == "1" || v == "true" || v == "on"
}

func (s *Server) consoleListAccounts(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	status := app.ParseStatusFilter(r.URL.Query().Get("status"))
	includeSelf := parseIncludeSelf(r)
	items, err := s.console.ListAccounts(r.Context(), app.ListAccountsQuery{Search: search, Status: status, IncludeSelf: includeSelf})
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Page(w, r, "accounts_list", http.StatusOK, adminweb.AccountListView{
		Base:        s.consoleBase(r, "Contas", "accounts"),
		Accounts:    adminweb.ToAccountListItems(items),
		Search:      search,
		Status:      string(status),
		IncludeSelf: includeSelf,
	})
}

func (s *Server) consoleAccountRows(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	status := app.ParseStatusFilter(r.URL.Query().Get("status"))
	includeSelf := parseIncludeSelf(r)
	items, err := s.console.ListAccounts(r.Context(), app.ListAccountsQuery{Search: search, Status: status, IncludeSelf: includeSelf})
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Partial(w, http.StatusOK, "account_rows", adminweb.AccountRowsView{
		Accounts:    adminweb.ToAccountListItems(items),
		Search:      search,
		IncludeSelf: includeSelf,
	})
}

func (s *Server) consoleNewAccountForm(w http.ResponseWriter, r *http.Request) {
	s.ui.Page(w, r, "account_new", http.StatusOK, adminweb.NewAccountView{
		Base:   s.consoleBase(r, "Nova conta", "accounts"),
		Form:   map[string]string{},
		Errors: map[string]string{},
	})
}

func (s *Server) consoleCreateAccount(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	a, err := s.console.CreateAccount(r.Context(), name)
	if err != nil {
		if isServiceError(err) {
			s.consoleError(w, err)
			return
		}
		s.ui.Page(w, r, "account_new", http.StatusUnprocessableEntity, adminweb.NewAccountView{
			Base:   s.consoleBase(r, "Nova conta", "accounts"),
			Form:   map[string]string{"name": name},
			Errors: fieldErrors(err, "name"),
		})
		return
	}
	s.ui.BodyWithOOB(w, http.StatusOK, "account_detail",
		adminweb.AccountDetailView{Base: s.consoleBase(r, a.Name(), "accounts"), Account: adminweb.ToAccountView(a)},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "Conta criada."}})
}

// --- Conta detail + lifecycle + nested empresas-clientes ---

func (s *Server) consoleAccountDetail(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	a, err := s.console.GetAccount(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	tenants, err := s.console.ListTenantsByAccount(r.Context(), a.ID())
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Page(w, r, "account_detail", http.StatusOK, adminweb.AccountDetailView{
		Base:    s.consoleBase(r, a.Name(), "accounts"),
		Account: adminweb.ToAccountView(a),
		Tenants: adminweb.ToTenantViews(tenants),
	})
}

func (s *Server) consoleSuspendAccount(w http.ResponseWriter, r *http.Request) {
	s.accountTransition(w, r, s.console.SuspendAccount, "Conta suspensa.")
}

func (s *Server) consoleActivateAccount(w http.ResponseWriter, r *http.Request) {
	s.accountTransition(w, r, s.console.ActivateAccount, "Conta reativada.")
}

// accountTransition runs an account lifecycle change and replies with pure
// out-of-band swaps (badge + toggle update in place, plus a toast), mirroring the
// tenant transition. v1: no effect on the empresas-clientes' auth (spec §7).
func (s *Server) accountTransition(w http.ResponseWriter, r *http.Request, op func(context.Context, string) (*account.Account, error), msg string) {
	acctID := chi.URLParam(r, "acctId")
	a, err := op(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	av := adminweb.ToAccountView(a)
	s.ui.Partials(w, http.StatusOK,
		adminweb.OOBPart{Name: "account_status_header_oob", Data: av},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: msg}})
}

func (s *Server) consoleNewAccountTenantForm(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	a, err := s.console.GetAccount(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Page(w, r, "account_tenant_new", http.StatusOK, adminweb.NewAccountTenantView{
		Base:    s.consoleBase(r, "Nova empresa-cliente", "accounts"),
		Account: adminweb.ToAccountView(a),
		Form:    map[string]string{},
		Errors:  map[string]string{},
	})
}

func (s *Server) consoleCreateAccountTenant(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	a, err := s.console.GetAccount(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	t, err := s.console.CreateTenantUnderAccount(r.Context(), a.ID(), name)
	if err != nil {
		if isServiceError(err) {
			s.consoleError(w, err)
			return
		}
		s.ui.Page(w, r, "account_tenant_new", http.StatusUnprocessableEntity, adminweb.NewAccountTenantView{
			Base:    s.consoleBase(r, "Nova empresa-cliente", "accounts"),
			Account: adminweb.ToAccountView(a),
			Form:    map[string]string{"name": name},
			Errors:  fieldErrors(err, "name"),
		})
		return
	}
	tv := adminweb.ToTenantView(t)
	tv.AccountID = a.ID()
	tv.AccountName = a.Name()
	s.ui.BodyWithOOB(w, http.StatusOK, "tenant_detail",
		adminweb.DetailView{Base: s.consoleBase(r, t.Name(), "accounts"), Tenant: tv},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "Empresa-cliente criada e vinculada à Conta."}})
}

// --- Uso por Conta (rollup) ---

// accountTenantNames maps each empresa-cliente id under an account to its display
// name, so the rollup and invoice screens can label rows without a per-row lookup.
func (s *Server) accountTenantNames(ctx context.Context, acctID string) (map[string]string, error) {
	tenants, err := s.console.ListTenantsByAccount(ctx, acctID)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(tenants))
	for _, t := range tenants {
		m[t.ID()] = t.Name()
	}
	return m, nil
}

func (s *Server) consoleAccountConsumption(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	a, err := s.console.GetAccount(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view, err := s.accountConsumptionView(r, a)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view.Base = s.consoleBase(r, "Uso por Conta", "accounts")
	s.ui.Page(w, r, "account_consumption", http.StatusOK, view)
}

func (s *Server) consoleAccountConsumptionRows(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	a, err := s.console.GetAccount(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view, err := s.accountConsumptionView(r, a)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	s.ui.Partial(w, http.StatusOK, "account_consumption_rows", view)
}

// accountConsumptionView assembles the account rollup view-model for the active
// date window, reused by the page render and the filter-swap partial.
func (s *Server) accountConsumptionView(r *http.Request, a *account.Account) (adminweb.AccountConsumptionView, error) {
	rng, startStr, endStr, err := parseConsumptionRange(r, s.console.Now())
	if err != nil {
		return adminweb.AccountConsumptionView{}, err
	}
	rep, err := s.console.AccountConsumptionInRange(r.Context(), a.ID(), rng)
	if err != nil {
		return adminweb.AccountConsumptionView{}, err
	}
	names, err := s.accountTenantNames(r.Context(), a.ID())
	if err != nil {
		return adminweb.AccountConsumptionView{}, err
	}
	view := adminweb.ToAccountConsumptionView(adminweb.ToAccountView(a), rep, names)
	view.StartDate, view.EndDate = startStr, endStr
	return view, nil
}

func (s *Server) consoleAccountConsumptionCSV(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	a, err := s.console.GetAccount(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	rng, startStr, endStr, err := parseConsumptionRange(r, s.console.Now())
	if err != nil {
		s.consoleError(w, err)
		return
	}
	rep, err := s.console.AccountConsumptionInRange(r.Context(), a.ID(), rng)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	names, err := s.accountTenantNames(r.Context(), a.ID())
	if err != nil {
		s.consoleError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// startStr/endStr are validated YYYY-MM-DD, so the filename carries no
	// user-controlled bytes (no header-injection surface).
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"uso-conta-%s-a-%s.csv\"", startStr, endStr))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"empresa_cliente_id", "empresa_cliente", "chamadas", "total_centavos", "total_reais"})
	for _, tc := range rep.Tenants {
		name := names[tc.TenantID]
		if name == "" {
			name = tc.TenantID
		}
		_ = cw.Write([]string{tc.TenantID, csvSafe(name), strconv.Itoa(tc.TotalCalls), strconv.FormatInt(tc.TotalCents, 10), centsDecimal(tc.TotalCents)})
	}
	_ = cw.Write([]string{"TOTAL", "", strconv.Itoa(rep.TotalCalls), strconv.FormatInt(rep.TotalCents, 10), centsDecimal(rep.TotalCents)})
	cw.Flush()
}

// --- Faturas por Conta ---

func (s *Server) consoleAccountInvoices(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	a, err := s.console.GetAccount(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	_, startStr, endStr, err := parseConsumptionRange(r, s.console.Now())
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view, err := s.accountInvoicesView(r, a)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view.StartDate, view.EndDate = startStr, endStr
	view.Base = s.consoleBase(r, "Faturas por Conta", "accounts")
	s.ui.Page(w, r, "account_invoices", http.StatusOK, view)
}

func (s *Server) consoleGenerateAccountInvoices(w http.ResponseWriter, r *http.Request) {
	acctID := chi.URLParam(r, "acctId")
	a, err := s.console.GetAccount(r.Context(), acctID)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	rng, startStr, endStr, err := parseInvoicePeriod(r)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	// Idempotency token from the hidden form nonce (SIN-69184): a double-submit
	// resubmits the same token and is deduped into the first submission's invoices,
	// so a double click never appends duplicate Faturas. A fresh render carries a
	// fresh token, so a deliberate regeneration still appends.
	idemKey := strings.TrimSpace(r.PostFormValue("idempotency_key"))
	gen, err := s.console.GenerateAccountInvoices(r.Context(), a.ID(), rng, app.WithIdempotencyKey(idemKey))
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view, err := s.accountInvoicesView(r, a)
	if err != nil {
		s.consoleError(w, err)
		return
	}
	view.StartDate, view.EndDate = startStr, endStr
	view.Base = s.consoleBase(r, "Faturas por Conta", "accounts")
	msg := fmt.Sprintf("%d fatura(s) gerada(s) no período.", len(gen))
	if len(gen) == 0 {
		msg = "Nenhuma empresa-cliente teve consumo no período; nenhuma fatura gerada."
	}
	s.ui.BodyWithOOB(w, http.StatusOK, "account_invoices", view,
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: msg}})
}

// accountInvoicesView assembles the account Faturas view-model (invoices per
// empresa-cliente grouped under the account), reused by the list and the batch swap.
func (s *Server) accountInvoicesView(r *http.Request, a *account.Account) (adminweb.AccountInvoicesView, error) {
	invs, err := s.console.ListInvoicesByAccount(r.Context(), a.ID())
	if err != nil {
		return adminweb.AccountInvoicesView{}, err
	}
	names, err := s.accountTenantNames(r.Context(), a.ID())
	if err != nil {
		return adminweb.AccountInvoicesView{}, err
	}
	view := adminweb.ToAccountInvoicesView(adminweb.ToAccountView(a), invs, names)
	// Mint a fresh per-render idempotency nonce for the batch-generation form
	// (SIN-69184). Both the list render and the post-generation re-render pass
	// through here, so each rendered form carries its own token.
	view.IdempotencyToken = newIdempotencyToken()
	return view, nil
}

// newIdempotencyToken mints an unguessable per-render nonce (128 bits, hex) for
// the batch-invoice form's double-submit guard. On the vanishingly unlikely event
// the CSPRNG fails, it returns "" — an empty token simply disables the guard for
// that render (fail-open to today's append-only behaviour), never blocking the
// admin from generating invoices.
func newIdempotencyToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
