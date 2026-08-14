package http_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newInvoiceConsoleHandler builds a console server with the invoice store + audit
// wired and a seeded tenant "t1", returning the router and the backing store.
func newInvoiceConsoleHandler(t *testing.T) (http.Handler, *persistence.Store) {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	if err := store.SaveTenant(context.Background(), tenant.Rehydrate("t1", "Acme", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed: %v", err)
	}
	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Pricing: store, Ledger: store, Invoices: store, Audit: store,
		CredWriter: creds, CredReader: creds,
		Clock: fixedClock{}, IDs: &seqIDs{},
	})
	ui, err := adminweb.New()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	auth := httpadapter.NewStaticTokenAuthWithRoles(nil, map[string]httpadapter.Role{
		adminToken:    httpadapter.RoleAdmin,
		operatorToken: httpadapter.RoleOperator,
	}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Console: console, UI: ui, AdminAuth: auth, TenantAuth: auth, WebhookAuth: auth,
	})
	return srv.Router(), store
}

func seedLedgerAt(t *testing.T, store *persistence.Store, tenantID, endpoint string, cents int64, at time.Time) {
	t.Helper()
	e, err := billing.NewLedgerEntry("led-"+at.Format("20060102150405"), tenantID, endpoint, "ref", cents, at)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	if err := store.AppendLedgerEntry(context.Background(), e); err != nil {
		t.Fatalf("append ledger: %v", err)
	}
}

func TestConsoleInvoicesListRenders(t *testing.T) {
	t.Parallel()
	h, _ := newInvoiceConsoleHandler(t)
	rec := consoleGet(t, h, "/console/tenants/t1/invoices", operatorToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Faturas") || !strings.Contains(rec.Body.String(), "Nenhuma fatura") {
		t.Fatalf("body missing empty-state: %s", rec.Body.String())
	}
	// Unknown tenant 404s cleanly.
	if r := consoleGet(t, h, "/console/tenants/ghost/invoices", operatorToken); r.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant = %d, want 404", r.Code)
	}
}

func TestConsoleGenerateInvoiceAndDownloadCSV(t *testing.T) {
	t.Parallel()
	h, store := newInvoiceConsoleHandler(t)
	seedLedgerAt(t, store, "t1", "POST /v1/charges", 250, time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC))
	seedLedgerAt(t, store, "t1", "GET /v1/charges", 10, time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC))

	csrf := csrfToken(t, h, adminToken)
	form := url.Values{"start_date": {"2026-08-01"}, "end_date": {"2026-08-05"}}
	rec := consolePost(t, h, "/console/tenants/t1/invoices", adminToken, form, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	// The generated invoice appears in the refreshed list with its total (R$ 2,60).
	if !strings.Contains(rec.Body.String(), "2,60") || !strings.Contains(rec.Body.String(), "Fatura gerada") {
		t.Fatalf("generate response missing invoice/toast: %s", rec.Body.String())
	}
	// The invoice was persisted append-only.
	invs, err := store.ListInvoices(context.Background(), "t1")
	if err != nil || len(invs) != 1 {
		t.Fatalf("persisted invoices = %d, %v", len(invs), err)
	}
	// Download it as CSV (seqIDs mints the constant id "gen-id").
	dl := consoleGet(t, h, "/console/tenants/t1/invoices/"+invs[0].ID()+".csv", operatorToken)
	if dl.Code != http.StatusOK {
		t.Fatalf("csv = %d, want 200", dl.Code)
	}
	if ct := dl.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type = %q", ct)
	}
	body := dl.Body.String()
	if !strings.Contains(body, "POST /v1/charges") || !strings.Contains(body, "TOTAL") || !strings.Contains(body, "2.60") {
		t.Fatalf("csv body unexpected: %s", body)
	}
	// The displayed period end is the last billed day (exclusive end − 1) = the
	// end_date the operator picked.
	if cd := dl.Header().Get("Content-Disposition"); !strings.Contains(cd, "fatura-2026-08-01-a-2026-08-05.csv") {
		t.Fatalf("content-disposition = %q", cd)
	}
}

func TestConsoleGenerateInvoiceRBACAndValidation(t *testing.T) {
	t.Parallel()
	h, _ := newInvoiceConsoleHandler(t)
	// Operator (read role) cannot generate — 403 (deny-by-default on the mutation).
	csrf := csrfToken(t, h, operatorToken)
	form := url.Values{"start_date": {"2026-08-01"}, "end_date": {"2026-08-05"}}
	if rec := consolePost(t, h, "/console/tenants/t1/invoices", operatorToken, form, csrf); rec.Code != http.StatusForbidden {
		t.Fatalf("operator generate = %d, want 403", rec.Code)
	}
	// Admin with missing dates → 400 (an invoice needs a bounded period).
	csrfA := csrfToken(t, h, adminToken)
	if rec := consolePost(t, h, "/console/tenants/t1/invoices", adminToken, url.Values{}, csrfA); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing dates = %d, want 400", rec.Code)
	}
}

func TestConsoleInvoiceCSVUnknown404(t *testing.T) {
	t.Parallel()
	h, _ := newInvoiceConsoleHandler(t)
	if rec := consoleGet(t, h, "/console/tenants/t1/invoices/ghost.csv", operatorToken); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown invoice csv = %d, want 404", rec.Code)
	}
}

// TestConsoleInvoiceCSVFormulaInjectionNeutralized is the defence-in-depth
// regression for SIN-69183 (CWE-1236) on the frozen-invoice export: an endpoint
// label beginning with a formula-trigger character must be neutralized
// (single-quote prefix) in the downloaded CSV. Fails on pre-fix code, passes after.
func TestConsoleInvoiceCSVFormulaInjectionNeutralized(t *testing.T) {
	t.Parallel()
	h, store := newInvoiceConsoleHandler(t)
	seedLedgerAt(t, store, "t1", "@SUM(1+1)", 250, time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC))

	csrf := csrfToken(t, h, adminToken)
	form := url.Values{"start_date": {"2026-08-01"}, "end_date": {"2026-08-05"}}
	if rec := consolePost(t, h, "/console/tenants/t1/invoices", adminToken, form, csrf); rec.Code != http.StatusOK {
		t.Fatalf("generate = %d: %s", rec.Code, rec.Body.String())
	}
	invs, err := store.ListInvoices(context.Background(), "t1")
	if err != nil || len(invs) != 1 {
		t.Fatalf("persisted invoices = %d, %v", len(invs), err)
	}
	dl := consoleGet(t, h, "/console/tenants/t1/invoices/"+invs[0].ID()+".csv", operatorToken)
	if dl.Code != http.StatusOK {
		t.Fatalf("csv = %d", dl.Code)
	}
	if body := dl.Body.String(); !strings.Contains(body, `'@SUM(1+1)`) {
		t.Fatalf("formula not neutralized in invoice CSV:\n%s", body)
	}
}
