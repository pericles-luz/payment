package adminweb

import (
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

// Base carries the layout-level fields every full page needs. CSRF is the
// per-request double-submit token echoed into forms and the hx-headers config;
// Role is the operator's display label (RBAC is enforced at the boundary).
type Base struct {
	Title string
	Nav   string
	CSRF  string
	Role  string
}

// NewBase builds the layout fields for a page.
func NewBase(title, nav, csrf, role string) Base {
	return Base{Title: title, Nav: nav, CSRF: csrf, Role: role}
}

// TenantView is the template-facing projection of a tenant. It exposes only what
// the UI renders and never carries secrets.
type TenantView struct {
	ID        string
	Name      string
	Active    bool
	CreatedAt time.Time
}

// ToTenantView projects a domain tenant for rendering.
func ToTenantView(t *tenant.Tenant) TenantView {
	return TenantView{ID: t.ID(), Name: t.Name(), Active: t.Active(), CreatedAt: t.CreatedAt()}
}

// ToTenantViews projects a slice of domain tenants for rendering.
func ToTenantViews(ts []*tenant.Tenant) []TenantView {
	out := make([]TenantView, 0, len(ts))
	for _, t := range ts {
		out = append(out, ToTenantView(t))
	}
	return out
}

// CreatedAtBR renders the creation date in Brazilian format.
func (v TenantView) CreatedAtBR() string { return v.CreatedAt.Format("02/01/2006") }

// ListView backs the tenant list screen.
type ListView struct {
	Base
	Tenants []TenantView
	Search  string
	Status  string
}

// RowsView backs the #tenant-rows fragment for search/filter swaps.
type RowsView struct {
	Tenants []TenantView
	Search  string
}

// NewTenantView backs the create-tenant form, echoing values and per-field
// validation errors for inline re-rendering.
type NewTenantView struct {
	Base
	Form   map[string]string
	Errors map[string]string
}

// DetailView backs the tenant detail screen.
type DetailView struct {
	Base
	Tenant TenantView
}

// PriceRow is one endpoint price in the pricing screen.
type PriceRow struct {
	Endpoint   string
	PriceCents int64
}

// PriceReais renders the price in Brazilian currency (R$ 0,00).
func (r PriceRow) PriceReais() string { return reais(r.PriceCents) }

// PricingView backs the per-tenant pricing screen (list + inline upsert form).
type PricingView struct {
	Base
	Tenant TenantView
	Prices []PriceRow
	Form   map[string]string
	Errors map[string]string
}

// ToPriceRows projects domain pricing rules for rendering.
func ToPriceRows(ps []billing.EndpointPricing) []PriceRow {
	out := make([]PriceRow, 0, len(ps))
	for _, p := range ps {
		out = append(out, PriceRow{Endpoint: p.Endpoint(), PriceCents: p.PriceCents()})
	}
	return out
}

// CredentialView backs the write-only bank-credential form. It never carries the
// secret; ClientID is echoed only after a successful write for confirmation.
type CredentialView struct {
	Base
	Tenant TenantView
	Form   map[string]string
	Errors map[string]string
	Saved  bool
}

// ConsumptionRow is one endpoint's aggregated usage in the consumption screen.
type ConsumptionRow struct {
	Endpoint   string
	Calls      int
	TotalCents int64
}

// TotalReais renders the row total in Brazilian currency.
func (r ConsumptionRow) TotalReais() string { return reais(r.TotalCents) }

// ConsumptionView backs the read-only consumption-audit screen.
type ConsumptionView struct {
	Base
	Tenant     TenantView
	Rows       []ConsumptionRow
	TotalCalls int
	TotalCents int64
}

// TotalReais renders the grand total in Brazilian currency.
func (v ConsumptionView) TotalReais() string { return reais(v.TotalCents) }

// ToConsumptionView projects a domain consumption report for rendering.
func ToConsumptionView(t TenantView, rep app.ConsumptionReport) ConsumptionView {
	rows := make([]ConsumptionRow, 0, len(rep.Lines))
	for _, l := range rep.Lines {
		rows = append(rows, ConsumptionRow{Endpoint: l.Endpoint, Calls: l.Calls, TotalCents: l.TotalCents})
	}
	return ConsumptionView{Tenant: t, Rows: rows, TotalCalls: rep.TotalCalls, TotalCents: rep.TotalCents}
}

// ToastData backs an out-of-band toast notification.
type ToastData struct {
	Kind    string // "success" | "danger" | "info"
	Message string
}

// reais formats integer cents as Brazilian currency: "R$ 1.234,56". Negative
// values are not expected (prices/charges are non-negative) but are formatted
// defensively rather than panicking.
func reais(cents int64) string {
	neg := cents < 0
	if neg {
		cents = -cents
	}
	intPart := cents / 100
	frac := cents % 100
	// Group the integer part with thousands separators ('.').
	digits := itoa(intPart)
	var grouped []byte
	for i, d := range []byte(digits) {
		if i > 0 && (len(digits)-i)%3 == 0 {
			grouped = append(grouped, '.')
		}
		grouped = append(grouped, d)
	}
	out := "R$ " + string(grouped) + "," + pad2(frac)
	if neg {
		out = "-" + out
	}
	return out
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func pad2(n int64) string {
	s := itoa(n)
	if len(s) < 2 {
		return "0" + s
	}
	return s
}
