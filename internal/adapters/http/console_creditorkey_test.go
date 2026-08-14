package http_test

import (
	"context"
	"net/http"
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
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

type creditorFixture struct {
	handler http.Handler
	creds   *secret.Store
	log     *auditlog.Log
}

// newCreditorFixture wires the console with the creditor-key write path + audit
// log, seeding tenant "t1" (with a c6 bank credential) and tenant "t2" (no
// credential) so all card states are reachable.
func newCreditorFixture(t *testing.T) *creditorFixture {
	t.Helper()
	store := persistence.NewStore()
	for _, ten := range []*tenant.Tenant{
		tenant.Rehydrate("t1", "Acme", true, time.Unix(100, 0).UTC()),
		tenant.Rehydrate("t2", "NoCred", true, time.Unix(100, 0).UTC()),
	} {
		if err := store.SaveTenant(context.Background(), ten); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	creds := secret.NewStore(map[string]ports.BankCredential{
		"t1": {TenantID: "t1", BankID: ports.BankIDC6, ClientID: "client-1", Secret: "secret-1"},
	})
	log := auditlog.NewLog()
	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Pricing: store, Ledger: store,
		CredWriter: creds, CreditorWriter: creds, CredReader: creds, Audit: log,
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
	return &creditorFixture{handler: srv.Router(), creds: creds, log: log}
}

// TestConsoleBankDetail_CreditorCardEditable asserts the bank detail page now
// renders an editable creditor-key card (the #72 read-only placeholder is gone).
func TestConsoleBankDetail_CreditorCardEditable(t *testing.T) {
	t.Parallel()
	f := newCreditorFixture(t)
	rec := consoleGet(t, f.handler, "/console/tenants/t1/banks/c6", adminToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `id="creditor-card"`) {
		t.Errorf("no creditor card: %s", body)
	}
	if !strings.Contains(body, `name="creditor_key"`) {
		t.Errorf("creditor card is not editable (no form field): %s", body)
	}
}

func TestConsoleSetCreditorKey_HappyPath(t *testing.T) {
	t.Parallel()
	f := newCreditorFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)
	const key = "recebedor@acme.com.br"

	rec := consolePost(t, f.handler, "/console/tenants/t1/creditor-key", adminToken, url.Values{"creditor_key": {key}}, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// Card-only swap: the creditor card re-renders, not the whole bank-detail page.
	if !strings.Contains(body, `id="creditor-card"`) {
		t.Errorf("response is not the creditor card: %s", body)
	}
	if strings.Contains(body, "Client ID") {
		t.Errorf("response leaked the credential card (should be creditor-card only): %s", body)
	}
	if !strings.Contains(body, "salva") {
		t.Errorf("missing success banner: %s", body)
	}
	// The persisted key IS shown as the read display (it is the public PIX id), but
	// it is never echoed back into the input field value.
	if strings.Contains(body, `value="`+key+`"`) {
		t.Errorf("response echoed the key into the input value: %s", body)
	}
	// Persisted + audited + secret preserved.
	got, _ := f.creds.GetBankCredential(context.Background(), "t1", ports.BankIDC6)
	if got.CreditorKey != key || got.Secret != "secret-1" {
		t.Errorf("not persisted/preserved: %+v", got)
	}
	if f.log.Len() != 1 || f.log.Entries()[0].Action() != audit.ActionSetCreditorKey {
		t.Errorf("audit not emitted: len=%d", f.log.Len())
	}
}

func TestConsoleSetCreditorKey_InvalidKeyShowsFieldError(t *testing.T) {
	t.Parallel()
	f := newCreditorFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	rec := consolePost(t, f.handler, "/console/tenants/t1/creditor-key", adminToken, url.Values{"creditor_key": {"garbage"}}, csrf)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `id="creditor-card"`) {
		t.Errorf("not the card: %s", body)
	}
	if !strings.Contains(body, "PIX") { // field error mentions a valid PIX key
		t.Errorf("missing field error: %s", body)
	}
	if strings.Contains(body, `value="garbage"`) {
		t.Errorf("echoed the bad key: %s", body)
	}
	if f.log.Len() != 0 {
		t.Errorf("invalid key must not audit, got %d", f.log.Len())
	}
}

func TestConsoleSetCreditorKey_NoCredentialShowsBanner(t *testing.T) {
	t.Parallel()
	f := newCreditorFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	// t2 exists but has no bank credential → user-actionable precondition banner.
	rec := consolePost(t, f.handler, "/console/tenants/t2/creditor-key", adminToken, url.Values{"creditor_key": {"recebedor@acme.com.br"}}, csrf)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "credencial") {
		t.Errorf("missing precondition banner: %s", rec.Body.String())
	}
}

func TestConsoleSetCreditorKey_UnknownTenant404(t *testing.T) {
	t.Parallel()
	f := newCreditorFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	rec := consolePost(t, f.handler, "/console/tenants/ghost/creditor-key", adminToken, url.Values{"creditor_key": {"recebedor@acme.com.br"}}, csrf)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestConsoleSetCreditorKey_RBACAndCSRF asserts the inherited guards: an operator
// (read-only) is forbidden, and a missing CSRF double-submit token is rejected.
func TestConsoleSetCreditorKey_RBACAndCSRF(t *testing.T) {
	t.Parallel()
	f := newCreditorFixture(t)

	csrf := csrfToken(t, f.handler, operatorToken)
	rec := consolePost(t, f.handler, "/console/tenants/t1/creditor-key", operatorToken, url.Values{"creditor_key": {"recebedor@acme.com.br"}}, csrf)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator status = %d, want 403", rec.Code)
	}
	rec = consolePost(t, f.handler, "/console/tenants/t1/creditor-key", adminToken, url.Values{"creditor_key": {"recebedor@acme.com.br"}}, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("missing CSRF accepted (status %d)", rec.Code)
	}
	if f.log.Len() != 0 {
		t.Errorf("no write should have been audited, got %d", f.log.Len())
	}
}
