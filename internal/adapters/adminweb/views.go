package adminweb

import (
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/invoice"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
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
	// Account fields are the owning Conta (two-level tenancy, SIN-69157). They are
	// populated only where the screen shows the account link (the tenant detail);
	// elsewhere they stay zero and the templates simply omit the card. AccountIsSelf
	// marks a legacy self-account so the detail renders "Conta própria (legado)".
	AccountID     string
	AccountName   string
	AccountIsSelf bool
}

// HasAccount reports whether the account link/card should render (the owning
// account was resolved for this view).
func (v TenantView) HasAccount() bool { return v.AccountID != "" }

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

// --- Banks (multi-bank console, SIN-66017 / SIN-66086) ---

// bankDisplayName maps a bank slug to its human-facing name (presentation only).
// An unknown slug falls back to its upper-cased form so a newly-wired bank still
// renders reasonably before a friendly label is added here.
func bankDisplayName(slug string) string {
	switch slug {
	case ports.BankIDC6:
		return "C6 Bank"
	default:
		return strings.ToUpper(slug)
	}
}

// BankRow is the template-facing projection of one bank within a tenant. It never
// carries the secret: CredentialSet drives the "configurada / pendente" badge and
// ClientID / CreditorKey are non-secret identity fields echoed for operator
// recognition. Active mirrors the tenant lifecycle (a suspended tenant's banks
// cannot transact) so the row can reuse the shared status_badge partial.
type BankRow struct {
	TenantID      string
	Slug          string
	DisplayName   string
	CredentialSet bool
	ClientID      string
	CreditorKey   string
	Active        bool
	// Cert is the bank's mTLS certificate metadata (public only), or nil when no
	// certificate is configured. It drives the cert_status_badge and the detail card.
	Cert *CertMeta
}

// CreditorKeySet reports whether a creditor (PIX) key is pinned for this bank.
func (r BankRow) CreditorKeySet() bool { return strings.TrimSpace(r.CreditorKey) != "" }

// CertMeta is the template-facing projection of a bank's mTLS certificate. It is
// PUBLIC metadata only — there is no private-key field by construction, so it can
// never leak the key (threat C1/C4). LogValue() makes that explicit so the value
// is safe to log as a structured attribute. The status helpers expose the
// precomputed lifecycle band (computed server-side with the service clock) so the
// template stays logic-light.
type CertMeta struct {
	SubjectCN         string
	Issuer            string
	SerialNumber      string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time

	status       app.CertStatus
	daysToExpiry int
}

// StatusValid / StatusExpiring / StatusExpired / StatusNotYetValid expose the
// precomputed lifecycle band to the badge template (one is true at a time).
func (m *CertMeta) StatusValid() bool       { return m.status == app.CertStatusValid }
func (m *CertMeta) StatusExpiring() bool    { return m.status == app.CertStatusExpiringSoon }
func (m *CertMeta) StatusExpired() bool     { return m.status == app.CertStatusExpired }
func (m *CertMeta) StatusNotYetValid() bool { return m.status == app.CertStatusNotYetValid }

// DaysToExpiry is the magnitude of days until (or since) NotAfter, for the badge
// copy ("Expira em N dias" / "Expirado há N dias").
func (m *CertMeta) DaysToExpiry() int {
	if m.daysToExpiry < 0 {
		return -m.daysToExpiry
	}
	return m.daysToExpiry
}

// DaysUnit agrees the day count with "dia"/"dias".
func (m *CertMeta) DaysUnit() string {
	if m.DaysToExpiry() == 1 {
		return "dia"
	}
	return "dias"
}

// NotBeforeBR / NotAfterBR render the validity bounds in Brazilian date format.
func (m *CertMeta) NotBeforeBR() string { return m.NotBefore.Format("02/01/2006") }
func (m *CertMeta) NotAfterBR() string  { return m.NotAfter.Format("02/01/2006") }

// LogValue emits only the certificate's public metadata under structured logging,
// making explicit that no private-key material exists on this value (threat
// C1/C4). A nil receiver renders an "[absent]" group rather than panicking.
func (m *CertMeta) LogValue() slog.Value {
	if m == nil {
		return slog.StringValue("[absent]")
	}
	return slog.GroupValue(
		slog.String("subject_cn", m.SubjectCN),
		slog.String("fingerprint_sha256", m.FingerprintSHA256),
		slog.Time("not_before", m.NotBefore),
		slog.Time("not_after", m.NotAfter),
		slog.String("status", string(m.status)),
	)
}

// toCertMeta projects a bank's certificate info (nil when none) for rendering.
func toCertMeta(c *app.BankCertInfo) *CertMeta {
	if c == nil {
		return nil
	}
	return &CertMeta{
		SubjectCN:         c.SubjectCN,
		Issuer:            c.Issuer,
		SerialNumber:      c.SerialNumber,
		FingerprintSHA256: c.FingerprintSHA256,
		NotBefore:         c.NotBefore,
		NotAfter:          c.NotAfter,
		status:            c.Status,
		daysToExpiry:      c.DaysToExpiry,
	}
}

// toBankRow projects a domain bank info for rendering, stamped with its tenant id
// (for the row's links) and the tenant's lifecycle state.
func toBankRow(tenantID string, info app.BankInfo, active bool) BankRow {
	return BankRow{
		TenantID:      tenantID,
		Slug:          info.Slug,
		DisplayName:   bankDisplayName(info.Slug),
		CredentialSet: info.CredentialSet,
		ClientID:      info.ClientID,
		CreditorKey:   info.CreditorKey,
		Active:        active,
		Cert:          toCertMeta(info.Cert),
	}
}

// ToBankRows projects a tenant's banks for the list screen.
func ToBankRows(tenantID string, infos []app.BankInfo, active bool) []BankRow {
	out := make([]BankRow, 0, len(infos))
	for _, info := range infos {
		out = append(out, toBankRow(tenantID, info, active))
	}
	return out
}

// BankTypeOption is one selectable bank in the closed add-bank selector.
type BankTypeOption struct {
	Slug        string
	DisplayName string
}

// ToBankTypeOptions projects addable bank slugs into selector options.
func ToBankTypeOptions(slugs []string) []BankTypeOption {
	out := make([]BankTypeOption, 0, len(slugs))
	for _, s := range slugs {
		out = append(out, BankTypeOption{Slug: s, DisplayName: bankDisplayName(s)})
	}
	return out
}

// BankListView backs the bank list screen (banks.html): the tenant's configured
// banks plus the closed add-bank selector (supported banks not yet configured).
type BankListView struct {
	Base
	Tenant  TenantView
	Banks   []BankRow
	Addable []BankTypeOption
	Form    map[string]string
	Errors  map[string]string
}

// CanAdd reports whether any supported bank is still unconfigured (drives the
// enabled/disabled state of the add-bank selector).
func (v BankListView) CanAdd() bool { return len(v.Addable) > 0 }

// BankDetailView backs the bank detail screen (bank_detail.html): one bank's
// credential card (write-only) and creditor-key card. It never carries the secret.
// CreditorSaved drives the creditor-key card's success banner; CreditorEditable is
// true only for the default bank (BankIDC6), the single bank the bankless
// creditor-key write path targets (SIN-66092 / ADR-0008) — other banks render the
// key read-only. The current key (read display) comes from Bank.CreditorKey.
type BankDetailView struct {
	Base
	Tenant           TenantView
	Bank             BankRow
	Form             map[string]string
	Errors           map[string]string
	CredSaved        bool
	CreditorSaved    bool
	CreditorEditable bool
	// CertSaved drives the certificate card's success banner after an upload/rotation.
	CertSaved bool
}

// ConsumptionRow is one endpoint's aggregated usage in the consumption screen.
type ConsumptionRow struct {
	Endpoint   string
	Calls      int
	TotalCents int64
}

// TotalReais renders the row total in Brazilian currency.
func (r ConsumptionRow) TotalReais() string { return reais(r.TotalCents) }

// ConsumptionView backs the read-only consumption-audit screen. StartDate and
// EndDate are the active filter window in ISO form (YYYY-MM-DD) — they back the
// date inputs and the CSV export link so the export mirrors what is on screen.
type ConsumptionView struct {
	Base
	Tenant     TenantView
	Rows       []ConsumptionRow
	TotalCalls int
	TotalCents int64
	StartDate  string
	EndDate    string
}

// TotalReais renders the grand total in Brazilian currency.
func (v ConsumptionView) TotalReais() string { return reais(v.TotalCents) }

// CSVHref is the same-origin export link for the current tenant and filter
// window (CSP-friendly: a plain GET to a whitelisted route, no inline handler).
func (v ConsumptionView) CSVHref() string {
	return "/console/tenants/" + url.PathEscape(v.Tenant.ID) + "/consumption.csv?start_date=" + url.QueryEscape(v.StartDate) + "&end_date=" + url.QueryEscape(v.EndDate)
}

// ToConsumptionView projects a domain consumption report for rendering.
func ToConsumptionView(t TenantView, rep app.ConsumptionReport) ConsumptionView {
	rows := make([]ConsumptionRow, 0, len(rep.Lines))
	for _, l := range rep.Lines {
		rows = append(rows, ConsumptionRow{Endpoint: l.Endpoint, Calls: l.Calls, TotalCents: l.TotalCents})
	}
	return ConsumptionView{Tenant: t, Rows: rows, TotalCalls: rep.TotalCalls, TotalCents: rep.TotalCents}
}

// --- Invoices (Faturas, SIN-69121) ---

// InvoiceRow is one invoice in the tenant's Faturas list. Period and generated
// timestamps are pre-formatted (ISO date) for the template; money is exposed via
// TotalReais so the currency formatting stays in one place.
type InvoiceRow struct {
	ID         string
	PeriodFrom string
	PeriodTo   string
	Generated  string
	TotalCalls int
	TotalCents int64
}

// TotalReais renders the invoice total in Brazilian currency.
func (r InvoiceRow) TotalReais() string { return reais(r.TotalCents) }

// CSVHref is the same-origin download link for one invoice (a plain GET to a
// whitelisted route; CSP-friendly). The id is path-escaped.
func (r InvoiceRow) CSVHref(tenantID string) string {
	return "/console/tenants/" + url.PathEscape(tenantID) + "/invoices/" + url.PathEscape(r.ID) + ".csv"
}

// InvoicesView backs the "Faturas" screen: the tenant's generated invoices plus
// the period picker that drives generation. StartDate/EndDate echo the chosen
// window back into the date inputs.
type InvoicesView struct {
	Base
	Tenant    TenantView
	Rows      []InvoiceRow
	StartDate string
	EndDate   string
}

// ToInvoicesView projects a tenant's invoices for the list screen. Timestamps are
// rendered as ISO dates (YYYY-MM-DD); the invoice period is half-open, so the
// display end is the stored exclusive end minus one day (the last billed day).
func ToInvoicesView(t TenantView, invs []invoice.Invoice) InvoicesView {
	rows := make([]InvoiceRow, 0, len(invs))
	for _, inv := range invs {
		rows = append(rows, InvoiceRow{
			ID:         inv.ID(),
			PeriodFrom: inv.PeriodStart().UTC().Format("2006-01-02"),
			PeriodTo:   inv.PeriodEnd().UTC().AddDate(0, 0, -1).Format("2006-01-02"),
			Generated:  inv.GeneratedAt().UTC().Format("2006-01-02"),
			TotalCalls: inv.TotalCalls(),
			TotalCents: inv.TotalCents(),
		})
	}
	return InvoicesView{Tenant: t, Rows: rows}
}

// --- Accounts (two-level tenancy admin, SIN-69157 / spec SIN-69122) ---

// AccountView is the template-facing projection of an account (Conta). It never
// carries a secret (an account holds no credential by construction). IsSelf marks
// a derived self-account (the legacy 1:1 "acct-<tenantID>" backfill) so the UI can
// label it "Conta própria (legado)". TenantCount is populated only on the list.
type AccountView struct {
	ID          string
	Name        string
	Active      bool
	CreatedAt   time.Time
	IsSelf      bool
	TenantCount int
}

// CreatedAtBR renders the creation date in Brazilian format.
func (v AccountView) CreatedAtBR() string { return v.CreatedAt.Format("02/01/2006") }

// ToAccountView projects a domain account for rendering (no tenant count).
func ToAccountView(a *account.Account) AccountView {
	return AccountView{
		ID:        a.ID(),
		Name:      a.Name(),
		Active:    a.Active(),
		CreatedAt: a.CreatedAt(),
		IsSelf:    account.IsSelfAccountID(a.ID()),
	}
}

// ToAccountListItems projects account list items (account + empresa-cliente count)
// for the Contas list rows.
func ToAccountListItems(items []app.AccountListItem) []AccountView {
	out := make([]AccountView, 0, len(items))
	for _, it := range items {
		v := ToAccountView(it.Account)
		v.TenantCount = it.TenantCount
		out = append(out, v)
	}
	return out
}

// AccountListView backs the Contas list screen (accounts_list.html).
type AccountListView struct {
	Base
	Accounts    []AccountView
	Search      string
	Status      string
	IncludeSelf bool
}

// AccountRowsView backs the #account-rows fragment for search/filter swaps.
type AccountRowsView struct {
	Accounts    []AccountView
	Search      string
	IncludeSelf bool
}

// NewAccountView backs the create-account form, echoing values and per-field
// validation errors for inline re-rendering.
type NewAccountView struct {
	Base
	Form   map[string]string
	Errors map[string]string
}

// AccountDetailView backs the account overview: header + the nested
// empresas-clientes (tenants) owned by the account.
type AccountDetailView struct {
	Base
	Account AccountView
	Tenants []TenantView
}

// NewAccountTenantView backs the "create empresa-cliente under this account" form.
type NewAccountTenantView struct {
	Base
	Account AccountView
	Form    map[string]string
	Errors  map[string]string
}

// AccountTenantConsumptionRow is one empresa-cliente's rolled-up usage in the
// account consumption screen: total calls + total value in the window, with a link
// to that tenant's per-endpoint detail.
type AccountTenantConsumptionRow struct {
	TenantID   string
	TenantName string
	Calls      int
	TotalCents int64
}

// TotalReais renders the row total in Brazilian currency.
func (r AccountTenantConsumptionRow) TotalReais() string { return reais(r.TotalCents) }

// AccountConsumptionView backs the account usage rollup screen (per empresa-cliente).
type AccountConsumptionView struct {
	Base
	Account    AccountView
	Rows       []AccountTenantConsumptionRow
	TotalCalls int
	TotalCents int64
	StartDate  string
	EndDate    string
}

// TotalReais renders the account grand total in Brazilian currency.
func (v AccountConsumptionView) TotalReais() string { return reais(v.TotalCents) }

// CSVHref is the same-origin export link for the account rollup and filter window.
func (v AccountConsumptionView) CSVHref() string {
	return "/console/accounts/" + url.PathEscape(v.Account.ID) + "/consumption.csv?start_date=" + url.QueryEscape(v.StartDate) + "&end_date=" + url.QueryEscape(v.EndDate)
}

// ToAccountConsumptionView projects an account rollup report for rendering. names
// resolves each tenant id to its display name (falling back to the id when a name
// is unavailable, so a row is never blank).
func ToAccountConsumptionView(acct AccountView, rep app.AccountConsumptionReport, names map[string]string) AccountConsumptionView {
	rows := make([]AccountTenantConsumptionRow, 0, len(rep.Tenants))
	for _, tc := range rep.Tenants {
		name := names[tc.TenantID]
		if name == "" {
			name = tc.TenantID
		}
		rows = append(rows, AccountTenantConsumptionRow{
			TenantID:   tc.TenantID,
			TenantName: name,
			Calls:      tc.TotalCalls,
			TotalCents: tc.TotalCents,
		})
	}
	return AccountConsumptionView{
		Account:    acct,
		Rows:       rows,
		TotalCalls: rep.TotalCalls,
		TotalCents: rep.TotalCents,
	}
}

// AccountInvoiceRow is one empresa-cliente's invoice in the account Faturas list.
// It reuses the per-tenant InvoiceRow projection and adds the owning tenant's id
// and name so the account view can group and link the per-tenant CSV download.
type AccountInvoiceRow struct {
	InvoiceRow
	TenantID   string
	TenantName string
}

// CSVHref is the same-origin per-tenant download link for this invoice (reusing
// the existing tenant-scoped route, so no new download surface is added).
func (r AccountInvoiceRow) CSVHref() string { return r.InvoiceRow.CSVHref(r.TenantID) }

// AccountInvoicesView backs the account Faturas screen: every empresa-cliente's
// invoice grouped under the account, plus the batch period picker.
type AccountInvoicesView struct {
	Base
	Account    AccountView
	Rows       []AccountInvoiceRow
	TotalCents int64
	StartDate  string
	EndDate    string
	// IdempotencyToken is a per-render nonce embedded in the batch-generation form
	// (SIN-69184). A double-submit resubmits the same nonce and is deduped; a fresh
	// render mints a new one, so a deliberate regeneration still appends.
	IdempotencyToken string
}

// TotalReais renders the account invoices grand total in Brazilian currency.
func (v AccountInvoicesView) TotalReais() string { return reais(v.TotalCents) }

// ToAccountInvoicesView projects an account's invoices (across its tenants) for the
// list screen, stamping each with its tenant name (falling back to the id).
func ToAccountInvoicesView(acct AccountView, invs []invoice.Invoice, names map[string]string) AccountInvoicesView {
	rows := make([]AccountInvoiceRow, 0, len(invs))
	var total int64
	for _, inv := range invs {
		name := names[inv.TenantID()]
		if name == "" {
			name = inv.TenantID()
		}
		rows = append(rows, AccountInvoiceRow{
			InvoiceRow: InvoiceRow{
				ID:         inv.ID(),
				PeriodFrom: inv.PeriodStart().UTC().Format("2006-01-02"),
				PeriodTo:   inv.PeriodEnd().UTC().AddDate(0, 0, -1).Format("2006-01-02"),
				Generated:  inv.GeneratedAt().UTC().Format("2006-01-02"),
				TotalCalls: inv.TotalCalls(),
				TotalCents: inv.TotalCents(),
			},
			TenantID:   inv.TenantID(),
			TenantName: name,
		})
		total += inv.TotalCents()
	}
	return AccountInvoicesView{Account: acct, Rows: rows, TotalCents: total}
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
