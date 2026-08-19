package http_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// TestConsoleTenantDetailHasBancosTab asserts the credentials tab was replaced by
// the Bancos tab pointing at the new route.
func TestConsoleTenantDetailHasBancosTab(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	rec := consoleGet(t, f.handler, "/console/tenants/t1", adminToken)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "/console/tenants/t1/banks") || !strings.Contains(body, ">Bancos<") {
		t.Fatalf("detail tabs = %d, missing Bancos tab: %s", rec.Code, body)
	}
}

func TestConsoleBankListEmptyAndConfigured(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)

	// Empty: no configured bank → empty state + add-bank selector with C6.
	rec := consoleGet(t, f.handler, "/console/tenants/t1/banks", adminToken)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("banks = %d", rec.Code)
	}
	if !strings.Contains(body, "Nenhum banco configurado") {
		t.Fatalf("missing empty state: %s", body)
	}
	if !strings.Contains(body, "Adicionar banco") || !strings.Contains(body, "C6 Bank") {
		t.Fatalf("missing add-bank selector: %s", body)
	}

	// Configure C6, then it shows as a configured row.
	if err := f.creds.SetBankCredential(context.Background(), "t1", ports.BankIDC6, "cid-1", "s3cr3t"); err != nil {
		t.Fatalf("seed cred: %v", err)
	}
	rec = consoleGet(t, f.handler, "/console/tenants/t1/banks", adminToken)
	body = rec.Body.String()
	if !strings.Contains(body, "configurada") || !strings.Contains(body, "C6 Bank") {
		t.Fatalf("configured row missing: %s", body)
	}
	// No secret ever in the list.
	if strings.Contains(body, "s3cr3t") {
		t.Fatalf("secret leaked into bank list")
	}
	// Selector is exhausted → explanatory copy, no add form fields.
	if !strings.Contains(body, "já constam na lista") {
		t.Fatalf("expected exhausted-selector copy: %s", body)
	}
}

func TestConsoleBankDetail(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	// Pending bank detail renders the credential card.
	rec := consoleGet(t, f.handler, "/console/tenants/t1/banks/c6", adminToken)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Client ID") || !strings.Contains(body, "Chave PIX do recebedor") {
		t.Fatalf("detail = %d: %s", rec.Code, body)
	}
	if !strings.Contains(body, "pendente") {
		t.Fatalf("expected pendente badge: %s", body)
	}
	// Unknown bank → 404.
	if r := consoleGet(t, f.handler, "/console/tenants/t1/banks/nubank", adminToken); r.Code != http.StatusNotFound {
		t.Fatalf("unknown bank detail = %d, want 404", r.Code)
	}
	// Unknown tenant → 404.
	if r := consoleGet(t, f.handler, "/console/tenants/missing/banks/c6", adminToken); r.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant detail = %d, want 404", r.Code)
	}
}

func TestConsoleBankDetailShowsCreditorKey(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	f.creds.Set("t1", ports.BankCredential{BankID: ports.BankIDC6, ClientID: "cid-1", Secret: "s3cr3t", CreditorKey: "pix-key-1"})
	rec := consoleGet(t, f.handler, "/console/tenants/t1/banks/c6", adminToken)
	body := rec.Body.String()
	if !strings.Contains(body, "pix-key-1") || !strings.Contains(body, "configurada") {
		t.Fatalf("creditor key / configured badge missing: %s", body)
	}
	if strings.Contains(body, "s3cr3t") {
		t.Fatalf("secret leaked into bank detail")
	}
}

func TestConsoleAddBankNavigatesToDetail(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	ok := consolePost(t, f.handler, "/console/tenants/t1/banks", adminToken,
		url.Values{"bank_type": {"c6"}, "alias": {"principal"}}, csrf)
	body := ok.Body.String()
	if ok.Code != http.StatusOK || !strings.Contains(body, "Client ID") || !strings.Contains(body, "Banco adicionado") {
		t.Fatalf("add bank = %d: %s", ok.Code, body)
	}

	// The creditor-key form must be usable right here. Rendering the read-only card
	// instead told the operator that editing "is only available on the default bank" —
	// on the default bank's own page, immediately after being told to configure it. On a
	// fresh deployment this is the ONLY route to the page, so the wrong branch dead-ends
	// onboarding: the PIX key can never be set, and a charge without it has no QR.
	if !strings.Contains(body, `name="creditor_key"`) {
		t.Fatalf("creditor-key form must render on the default bank's detail: %s", body)
	}
	if strings.Contains(body, "apenas no banco padrão") {
		t.Fatalf("read-only creditor card must not render for the default bank: %s", body)
	}

	// Unknown bank slug (allow-list backstop) → 422 with inline error, no detail.
	bad := consolePost(t, f.handler, "/console/tenants/t1/banks", adminToken,
		url.Values{"bank_type": {"nubank"}}, csrf)
	if bad.Code != http.StatusUnprocessableEntity || !strings.Contains(bad.Body.String(), "não suportado") {
		t.Fatalf("add unknown bank = %d: %s", bad.Code, bad.Body.String())
	}
}

func TestConsoleSetBankCredentialPerBank(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	csrf := csrfToken(t, f.handler, adminToken)

	ok := consolePost(t, f.handler, "/console/tenants/t1/banks/c6/credential", adminToken,
		url.Values{"client_id": {"cid-1"}, "secret": {"s3cr3t"}}, csrf)
	body := ok.Body.String()
	if ok.Code != http.StatusOK || !strings.Contains(body, "Credencial salva") {
		t.Fatalf("set per-bank cred = %d: %s", ok.Code, body)
	}
	if strings.Contains(body, "s3cr3t") {
		t.Fatalf("secret leaked into card swap")
	}
	got, err := f.creds.GetBankCredential(context.Background(), "t1", ports.BankIDC6)
	if err != nil || got.ClientID != "cid-1" || got.Secret != "s3cr3t" {
		t.Fatalf("stored = %+v (%v)", got, err)
	}

	// Empty secret → 422 inline error.
	bad := consolePost(t, f.handler, "/console/tenants/t1/banks/c6/credential", adminToken,
		url.Values{"client_id": {"cid"}, "secret": {""}}, csrf)
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty secret = %d, want 422", bad.Code)
	}

	// Unknown bank → 404.
	miss := consolePost(t, f.handler, "/console/tenants/t1/banks/nubank/credential", adminToken,
		url.Values{"client_id": {"c"}, "secret": {"s"}}, csrf)
	if miss.Code != http.StatusNotFound {
		t.Fatalf("unknown bank cred = %d, want 404", miss.Code)
	}
}

// TestConsoleBankRBACOperatorReadOnly asserts Operator can read the bank screens
// but cannot mutate (add-bank / set-credential) — least privilege at the boundary.
func TestConsoleBankRBACOperatorReadOnly(t *testing.T) {
	t.Parallel()
	f := newConsoleFixture(t)
	if rec := consoleGet(t, f.handler, "/console/tenants/t1/banks", operatorToken); rec.Code != http.StatusOK {
		t.Fatalf("operator read banks = %d, want 200", rec.Code)
	}
	csrf := csrfToken(t, f.handler, operatorToken)
	add := consolePost(t, f.handler, "/console/tenants/t1/banks", operatorToken, url.Values{"bank_type": {"c6"}}, csrf)
	if add.Code != http.StatusForbidden {
		t.Fatalf("operator add bank = %d, want 403", add.Code)
	}
	cred := consolePost(t, f.handler, "/console/tenants/t1/banks/c6/credential", operatorToken,
		url.Values{"client_id": {"c"}, "secret": {"s"}}, csrf)
	if cred.Code != http.StatusForbidden {
		t.Fatalf("operator set cred = %d, want 403", cred.Code)
	}
}
