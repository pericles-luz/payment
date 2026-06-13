package adminweb_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

func newRenderer(t *testing.T) *adminweb.Renderer {
	t.Helper()
	rd, err := adminweb.New()
	if err != nil {
		t.Fatalf("new renderer: %v", err)
	}
	return rd
}

func listView() adminweb.ListView {
	tn := tenant.Rehydrate("t1", "Acme Ltda", true, time.Unix(1700000000, 0).UTC())
	return adminweb.ListView{
		Base:    adminweb.NewBase("Tenants", "tenants", "csrf-xyz", "operador · admin"),
		Tenants: adminweb.ToTenantViews([]*tenant.Tenant{tn}),
	}
}

func TestPageFullVsFragment(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)

	// Full navigation → whole document with the CSRF token wired in.
	full := httptest.NewRecorder()
	rd.Page(full, httptest.NewRequest(http.MethodGet, "/console/tenants", nil), "tenants_list", http.StatusOK, listView())
	body := full.Body.String()
	if full.Code != http.StatusOK || !strings.Contains(body, "<!doctype html>") {
		t.Fatalf("full page missing doctype: code=%d", full.Code)
	}
	if !strings.Contains(body, "csrf-xyz") || !strings.Contains(body, "Acme Ltda") {
		t.Fatalf("full page missing csrf/tenant: %s", body)
	}

	// htmx request → body fragment only (no doctype/layout).
	frag := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/console/tenants", nil)
	r.Header.Set("HX-Request", "true")
	rd.Page(frag, r, "tenants_list", http.StatusOK, listView())
	fb := frag.Body.String()
	if strings.Contains(fb, "<!doctype html>") {
		t.Fatalf("fragment should not contain doctype")
	}
	if !strings.Contains(fb, "Acme Ltda") {
		t.Fatalf("fragment missing tenant row")
	}
}

func TestPageUnknownScreen(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	w := httptest.NewRecorder()
	rd.Page(w, httptest.NewRequest(http.MethodGet, "/", nil), "nope", http.StatusOK, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("unknown screen code = %d, want 500", w.Code)
	}
}

func TestPartialAndPartials(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)

	w := httptest.NewRecorder()
	rd.Partial(w, http.StatusOK, "tenant_rows", adminweb.RowsView{Tenants: listView().Tenants})
	if !strings.Contains(w.Body.String(), "Acme Ltda") {
		t.Fatalf("partial missing row")
	}

	tv := adminweb.TenantView{ID: "t1", Name: "Acme", Active: false}
	w2 := httptest.NewRecorder()
	rd.Partials(w2, http.StatusOK,
		adminweb.OOBPart{Name: "status_header_oob", Data: tv},
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "ok"}})
	out := w2.Body.String()
	if !strings.Contains(out, "Suspenso") || !strings.Contains(out, "Reativar") || !strings.Contains(out, "ok") {
		t.Fatalf("oob partials unexpected: %s", out)
	}
}

func TestBodyWithOOB(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	w := httptest.NewRecorder()
	dv := adminweb.DetailView{
		Base:   adminweb.NewBase("Acme", "tenants", "c", "op"),
		Tenant: adminweb.TenantView{ID: "t1", Name: "Acme", Active: true},
	}
	rd.BodyWithOOB(w, http.StatusOK, "tenant_detail", dv,
		adminweb.OOBPart{Name: "toast_oob", Data: adminweb.ToastData{Kind: "success", Message: "criado"}})
	out := w.Body.String()
	if !strings.Contains(out, "Acme") || !strings.Contains(out, "criado") {
		t.Fatalf("body+oob unexpected: %s", out)
	}
}

func TestServeStatic(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)
	for _, name := range []string{"app.css", "tokens.css", "htmx.min.js"} {
		w := httptest.NewRecorder()
		rd.ServeStatic(w, name)
		if w.Code != http.StatusOK || w.Body.Len() == 0 {
			t.Fatalf("static %s: code=%d len=%d", name, w.Code, w.Body.Len())
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("static %s missing nosniff", name)
		}
	}
	w := httptest.NewRecorder()
	rd.ServeStatic(w, "../secret")
	if w.Code != http.StatusNotFound {
		t.Fatalf("disallowed static code = %d, want 404", w.Code)
	}
}

func TestViewHelpers(t *testing.T) {
	t.Parallel()
	// reais via PriceRow / ConsumptionRow.
	if got := (adminweb.PriceRow{PriceCents: 123456}).PriceReais(); got != "R$ 1.234,56" {
		t.Fatalf("PriceReais = %q", got)
	}
	if got := (adminweb.PriceRow{PriceCents: 5}).PriceReais(); got != "R$ 0,05" {
		t.Fatalf("PriceReais small = %q", got)
	}
	if got := (adminweb.ConsumptionRow{TotalCents: 0}).TotalReais(); got != "R$ 0,00" {
		t.Fatalf("zero = %q", got)
	}

	tn := tenant.Rehydrate("t1", "Acme", true, time.Date(2026, 6, 13, 0, 0, 0, 0, time.UTC))
	if got := adminweb.ToTenantView(tn).CreatedAtBR(); got != "13/06/2026" {
		t.Fatalf("CreatedAtBR = %q", got)
	}

	rep := app.ConsumptionReport{
		TenantID:   "t1",
		Lines:      []app.ConsumptionLine{{Endpoint: "POST", Calls: 2, TotalCents: 500}},
		TotalCalls: 2,
		TotalCents: 500,
	}
	cv := adminweb.ToConsumptionView(adminweb.ToTenantView(tn), rep)
	if len(cv.Rows) != 1 || cv.Rows[0].Calls != 2 || cv.TotalReais() != "R$ 5,00" {
		t.Fatalf("consumption view unexpected %+v", cv)
	}

	prices := adminweb.ToPriceRows([]billing.EndpointPricing{mustPrice(t, "t1", "GET", 10)})
	if len(prices) != 1 || prices[0].Endpoint != "GET" {
		t.Fatalf("ToPriceRows unexpected %+v", prices)
	}
}

func TestReaisNegative(t *testing.T) {
	t.Parallel()
	if got := (adminweb.PriceRow{PriceCents: -123456}).PriceReais(); got != "-R$ 1.234,56" {
		t.Fatalf("negative reais = %q", got)
	}
}

// TestRenderErrorPaths drives the buffered-error branches: an unknown screen and
// a template executed against incompatible data must yield a clean 500, never a
// half-written response.
func TestRenderErrorPaths(t *testing.T) {
	t.Parallel()
	rd := newRenderer(t)

	// BodyWithOOB with an unknown screen.
	w := httptest.NewRecorder()
	rd.BodyWithOOB(w, http.StatusOK, "nope", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("BodyWithOOB unknown screen = %d", w.Code)
	}

	// Partial executed against incompatible data (int has no .Tenants field).
	w2 := httptest.NewRecorder()
	rd.Partial(w2, http.StatusOK, "tenant_rows", 42)
	if w2.Code != http.StatusInternalServerError {
		t.Fatalf("Partial bad data = %d", w2.Code)
	}

	// Partials with an unknown partial name.
	w3 := httptest.NewRecorder()
	rd.Partials(w3, http.StatusOK, adminweb.OOBPart{Name: "missing_partial", Data: nil})
	if w3.Code != http.StatusInternalServerError {
		t.Fatalf("Partials unknown = %d", w3.Code)
	}

	// BodyWithOOB whose body executes but an OOB part fails.
	w4 := httptest.NewRecorder()
	dv := adminweb.DetailView{Tenant: adminweb.TenantView{ID: "t1", Name: "Acme"}}
	rd.BodyWithOOB(w4, http.StatusOK, "tenant_detail", dv, adminweb.OOBPart{Name: "missing", Data: nil})
	if w4.Code != http.StatusInternalServerError {
		t.Fatalf("BodyWithOOB bad oob = %d", w4.Code)
	}

	// Page executed against incompatible data.
	w5 := httptest.NewRecorder()
	rd.Page(w5, httptest.NewRequest(http.MethodGet, "/", nil), "consumption", http.StatusOK, 42)
	if w5.Code != http.StatusInternalServerError {
		t.Fatalf("Page bad data = %d", w5.Code)
	}
}

func mustPrice(t *testing.T, tenantID, endpoint string, cents int64) billing.EndpointPricing {
	t.Helper()
	p, err := billing.NewEndpointPricing(tenantID, endpoint, cents)
	if err != nil {
		t.Fatalf("price: %v", err)
	}
	return p
}
