package adminweb_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

func acctView(id, name string) adminweb.AccountView {
	return adminweb.ToAccountView(account.Rehydrate(id, name, true, time.Unix(1700000000, 0).UTC()))
}

func renderBody(t *testing.T, rd *adminweb.Renderer, screen string, data any) string {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/console/accounts", nil)
	r.Header.Set("HX-Request", "true")
	rd.Page(w, r, screen, http.StatusOK, data)
	if w.Code != http.StatusOK {
		t.Fatalf("%s render code = %d", screen, w.Code)
	}
	return w.Body.String()
}

func TestToAccountView_SelfClassification(t *testing.T) {
	t.Parallel()
	real := adminweb.ToAccountView(account.Rehydrate("verz-1", "Verz", true, time.Unix(1, 0).UTC()))
	if real.IsSelf {
		t.Fatalf("real account must not be self")
	}
	self := adminweb.ToAccountView(account.Rehydrate("acct-t9", "Legacy", true, time.Unix(1, 0).UTC()))
	if !self.IsSelf {
		t.Fatalf("acct- prefixed account must be self")
	}
}

func TestToAccountListItems_Counts(t *testing.T) {
	t.Parallel()
	items := []app.AccountListItem{
		{Account: account.Rehydrate("a", "Verz", true, time.Unix(1, 0).UTC()), TenantCount: 3},
	}
	views := adminweb.ToAccountListItems(items)
	if len(views) != 1 || views[0].TenantCount != 3 || views[0].Name != "Verz" {
		t.Fatalf("views = %+v", views)
	}
}

func TestAccountsListRender(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	view := adminweb.AccountListView{
		Base:     adminweb.NewBase("Contas", "accounts", "csrf-1", "operador · admin"),
		Accounts: []adminweb.AccountView{acctView("verz-1", "Verz Pagamentos")},
	}
	body := renderBody(t, rd, "accounts_list", view)
	if !strings.Contains(body, "Verz Pagamentos") || !strings.Contains(body, "/console/accounts/verz-1") {
		t.Fatalf("list body missing account: %s", body)
	}
	if !strings.Contains(body, "Mostrar contas próprias") {
		t.Fatalf("list body missing self toggle")
	}
	// Empty state.
	empty := renderBody(t, rd, "accounts_list", adminweb.AccountListView{Base: view.Base})
	if !strings.Contains(empty, "Nenhuma conta ainda") {
		t.Fatalf("empty state missing: %s", empty)
	}
}

func TestAccountDetailRender_NestedTenants(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	tn := tenant.Rehydrate("t1", "Cliente Um", true, time.Unix(1, 0).UTC())
	view := adminweb.AccountDetailView{
		Base:    adminweb.NewBase("Verz", "accounts", "csrf-1", "operador · admin"),
		Account: acctView("verz-1", "Verz"),
		Tenants: adminweb.ToTenantViews([]*tenant.Tenant{tn}),
	}
	body := renderBody(t, rd, "account_detail", view)
	if !strings.Contains(body, "Cliente Um") || !strings.Contains(body, "/console/tenants/t1") {
		t.Fatalf("detail missing nested tenant: %s", body)
	}
	if !strings.Contains(body, "/console/accounts/verz-1/consumption") {
		t.Fatalf("detail missing usage tab")
	}
	// Empty nested state offers the create action.
	empty := renderBody(t, rd, "account_detail", adminweb.AccountDetailView{Base: view.Base, Account: view.Account})
	if !strings.Contains(empty, "Nenhuma empresa-cliente nesta Conta") {
		t.Fatalf("empty nested state missing: %s", empty)
	}
}

func TestAccountConsumptionRender_RollupAndIsolation(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	rep := app.AccountConsumptionReport{
		AccountID: "verz-1",
		Tenants: []app.TenantConsumption{
			{TenantID: "t1", TotalCalls: 3, TotalCents: 510},
			{TenantID: "t2", TotalCalls: 1, TotalCents: 400},
		},
		TotalCalls: 4,
		TotalCents: 910,
	}
	names := map[string]string{"t1": "Cliente Um", "t2": "Cliente Dois"}
	view := adminweb.ToAccountConsumptionView(acctView("verz-1", "Verz"), rep, names)
	view.Base = adminweb.NewBase("Uso", "accounts", "csrf-1", "op")
	view.StartDate, view.EndDate = "2026-08-01", "2026-08-31"
	if view.TotalReais() != "R$ 9,10" {
		t.Fatalf("total = %q", view.TotalReais())
	}
	if !strings.Contains(view.CSVHref(), "/console/accounts/verz-1/consumption.csv?start_date=2026-08-01") {
		t.Fatalf("csv href = %q", view.CSVHref())
	}
	body := renderBody(t, rd, "account_consumption", view)
	if !strings.Contains(body, "Cliente Um") || !strings.Contains(body, "Total da Conta") {
		t.Fatalf("rollup body missing rows/total: %s", body)
	}
	// A missing name falls back to the tenant id (never blank).
	v2 := adminweb.ToAccountConsumptionView(acctView("verz-1", "Verz"),
		app.AccountConsumptionReport{Tenants: []app.TenantConsumption{{TenantID: "t9", TotalCalls: 1, TotalCents: 5}}}, nil)
	if v2.Rows[0].TenantName != "t9" {
		t.Fatalf("fallback name = %q", v2.Rows[0].TenantName)
	}
}

func TestAccountInvoicesRender(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	line, _ := invoice.NewLineItem("POST /v1/charges", 2, 500)
	inv, _ := invoice.New("inv-1", "t1", "verz-1",
		time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 6, 9, 0, 0, 0, time.UTC),
		[]invoice.LineItem{line})
	view := adminweb.ToAccountInvoicesView(acctView("verz-1", "Verz"), []invoice.Invoice{inv}, map[string]string{"t1": "Cliente Um"})
	view.Base = adminweb.NewBase("Faturas", "accounts", "csrf-1", "op")
	if view.TotalReais() != "R$ 5,00" {
		t.Fatalf("total = %q", view.TotalReais())
	}
	// The account invoice row reuses the per-tenant CSV download route.
	if href := view.Rows[0].CSVHref(); !strings.Contains(href, "/console/tenants/t1/invoices/inv-1.csv") {
		t.Fatalf("csv href = %q", href)
	}
	body := renderBody(t, rd, "account_invoices", view)
	if !strings.Contains(body, "Cliente Um") || !strings.Contains(body, "Gerar faturas do período") {
		t.Fatalf("invoices body missing content: %s", body)
	}
}

func TestAccountNewAndTenantNewRender(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	nv := adminweb.NewAccountView{Base: adminweb.NewBase("Nova conta", "accounts", "csrf-1", "op"), Form: map[string]string{}, Errors: map[string]string{"name": "obrigatório"}}
	if b := renderBody(t, rd, "account_new", nv); !strings.Contains(b, "obrigatório") {
		t.Fatalf("account_new missing error: %s", b)
	}
	tn := adminweb.NewAccountTenantView{Base: adminweb.NewBase("Nova empresa", "accounts", "csrf-1", "op"), Account: acctView("verz-1", "Verz"), Form: map[string]string{}, Errors: map[string]string{}}
	if b := renderBody(t, rd, "account_tenant_new", tn); !strings.Contains(b, "/console/accounts/verz-1/tenants") {
		t.Fatalf("account_tenant_new missing post target: %s", b)
	}
}

// TestTenantDetailAccountCard covers §5.3: the Conta card links a real account and
// shows "Conta própria (legado)" for a self/legacy tenant.
func TestTenantDetailAccountCard(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	tv := adminweb.TenantView{ID: "t1", Name: "Cliente", Active: true, CreatedAt: time.Unix(1, 0).UTC(), AccountID: "verz-1", AccountName: "Verz"}
	if !tv.HasAccount() {
		t.Fatalf("HasAccount should be true")
	}
	body := renderBody(t, rd, "tenant_detail", adminweb.DetailView{Base: adminweb.NewBase("Cliente", "tenants", "c", "op"), Tenant: tv})
	if !strings.Contains(body, "/console/accounts/verz-1") || !strings.Contains(body, "Verz") {
		t.Fatalf("account card link missing: %s", body)
	}
	// Legacy tenant (no account) → "Conta própria (legado)".
	legacy := adminweb.TenantView{ID: "t2", Name: "Legado", Active: true, CreatedAt: time.Unix(1, 0).UTC()}
	lb := renderBody(t, rd, "tenant_detail", adminweb.DetailView{Base: adminweb.NewBase("Legado", "tenants", "c", "op"), Tenant: legacy})
	if !strings.Contains(lb, "Conta própria (legado)") {
		t.Fatalf("legacy label missing: %s", lb)
	}
}
