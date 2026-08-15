package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/adminweb"
	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// editDeleteFixture wires the console with the full ADR-0012 surface: accounts, the
// audit log spy and the credential/certificate deleters. Seeds a real account
// "reseller-1" and a tenant "t1".
type editDeleteFixture struct {
	handler http.Handler
	creds   *secret.Store
	log     *auditlog.Log
}

func newEditDeleteFixture(t *testing.T) *editDeleteFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	certs := secret.NewCertStore()
	log := auditlog.NewLog()
	ctx := context.Background()
	if err := store.SaveTenant(ctx, tenant.Rehydrate("t1", "Acme", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	if err := store.SaveAccount(ctx, account.Rehydrate("reseller-1", "Verz", true, time.Unix(100, 0).UTC())); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Accounts: store, Pricing: store, Ledger: store,
		CredWriter: creds, CredReader: creds, CertWriter: certs, CertReader: certs,
		CredDeleter: creds, CertDeleter: certs, Audit: log,
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
	return &editDeleteFixture{handler: srv.Router(), creds: creds, log: log}
}

// consoleMethod submits a request with an arbitrary method, form body and CSRF.
func consoleMethod(t *testing.T, h http.Handler, method, path, token string, form url.Values, csrf *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if csrf != nil {
		req.AddCookie(csrf)
		req.Header.Set("X-CSRF-Token", csrf.Value)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestConsoleRenameTenant_HTTP(t *testing.T) {
	t.Parallel()
	f := newEditDeleteFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	// Happy path: 200, header name updated OOB, audit recorded.
	rec := consoleMethod(t, f.handler, http.MethodPatch, "/console/tenants/t1", adminToken, url.Values{"name": {"Acme Renamed"}}, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Acme Renamed") {
		t.Fatalf("response missing new name: %s", rec.Body.String())
	}
	// Blank name → 422 (inline validation).
	rec = consoleMethod(t, f.handler, http.MethodPatch, "/console/tenants/t1", adminToken, url.Values{"name": {"  "}}, csrf)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("blank rename = %d, want 422", rec.Code)
	}
	// Missing tenant → 404 (no oracle).
	rec = consoleMethod(t, f.handler, http.MethodPatch, "/console/tenants/missing", adminToken, url.Values{"name": {"X"}}, csrf)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing rename = %d, want 404", rec.Code)
	}
	// Operator (read-only) is refused the mutation.
	rec = consoleMethod(t, f.handler, http.MethodPatch, "/console/tenants/t1", operatorToken, url.Values{"name": {"Nope"}}, csrf)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator rename = %d, want 403", rec.Code)
	}
	// CSRF missing → 403.
	rec = consoleMethod(t, f.handler, http.MethodPatch, "/console/tenants/t1", adminToken, url.Values{"name": {"X"}}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-csrf rename = %d, want 403", rec.Code)
	}
}

func TestConsoleRenameAccount_HTTP(t *testing.T) {
	t.Parallel()
	f := newEditDeleteFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	rec := consoleMethod(t, f.handler, http.MethodPatch, "/console/accounts/reseller-1", adminToken, url.Values{"name": {"Verz Novo"}}, csrf)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Verz Novo") {
		t.Fatalf("rename account = %d: %s", rec.Code, rec.Body.String())
	}
	// Missing account → 404.
	rec = consoleMethod(t, f.handler, http.MethodPatch, "/console/accounts/missing", adminToken, url.Values{"name": {"X"}}, csrf)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing account rename = %d, want 404", rec.Code)
	}
}

func TestConsoleRemoveBank_HTTP(t *testing.T) {
	t.Parallel()
	f := newEditDeleteFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)
	ctx := context.Background()
	if err := f.creds.SetBankCredential(ctx, "t1", ports.BankIDC6, "client", "s3cr3t"); err != nil {
		t.Fatalf("seed cred: %v", err)
	}

	// Remove → 200, back to the bank list, credential gone, audit recorded.
	rec := consoleMethod(t, f.handler, http.MethodDelete, "/console/tenants/t1/banks/c6", adminToken, nil, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("remove = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if _, err := f.creds.GetBankCredential(ctx, "t1", ports.BankIDC6); err == nil {
		t.Fatal("credential must be removed")
	}
	found := false
	for _, e := range f.log.Entries() {
		if e.Action() == audit.ActionRemoveBankConfig {
			found = true
		}
	}
	if !found {
		t.Fatal("no bank_config.remove audit")
	}
	// Idempotent repeat still 200.
	rec = consoleMethod(t, f.handler, http.MethodDelete, "/console/tenants/t1/banks/c6", adminToken, nil, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent remove = %d, want 200", rec.Code)
	}
	// Unknown bank slug → 400.
	rec = consoleMethod(t, f.handler, http.MethodDelete, "/console/tenants/t1/banks/nubank", adminToken, nil, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown bank = %d, want 400", rec.Code)
	}
	// Missing tenant → 404.
	rec = consoleMethod(t, f.handler, http.MethodDelete, "/console/tenants/missing/banks/c6", adminToken, nil, csrf)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing tenant remove = %d, want 404", rec.Code)
	}
}
