package http_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
)

const pixKeyPath = "/v1/pix-key"

type pixKeyFixture struct {
	handler http.Handler
	tenantA string
	tenantB string
	tokenA  string
	creds   *secret.Store
}

// newPixKeyFixture wires the tenant plane WITH the console service, which owns the
// creditor-key write. Two tenants exist so a test can prove one cannot touch the
// other's key.
func newPixKeyFixture(t *testing.T, enabled bool) *pixKeyFixture {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	log := auditlog.NewLog()
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store, Processed: store,
		Bus: inmemory.NewBus(), Bank: stub, Credentials: creds, CredWriter: creds,
		Audit: log, Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	mk := func(name string) string {
		tn, err := admin.CreateTenant(context.Background(), name)
		if err != nil {
			t.Fatalf("seed tenant %s: %v", name, err)
		}
		return tn.ID()
	}
	tenantA, tenantB := mk("Acme"), mk("Globex")

	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store, Pricing: store, Ledger: store, Audit: log,
		CredWriter: creds, CredReader: creds, CreditorWriter: creds,
		Clock: system.Clock{}, IDs: system.IDProvider{},
	})
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{"tok-a": tenantA, "tok-b": tenantB}, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges: app.NewChargeService(deps), Admin: admin, Console: console,
		Webhooks:   app.NewWebhookService(deps),
		TenantAuth: auth, AdminAuth: auth, WebhookAuth: auth,
		SelfServeCredIntake: enabled,
	})
	// A chave PIX só pode ser gravada DEPOIS da credencial: o writer a guarda dentro
	// da credencial do par (tenant, banco), então sem ela não há onde escrever. É
	// ordem real do produto, não detalhe de teste — a tela precisa refletir isso.
	if err := admin.SetBankCredential(context.Background(), tenantA, "c6", "cid-a", "s3cr3t"); err != nil {
		t.Fatalf("semear credencial: %v", err)
	}
	return &pixKeyFixture{handler: srv.Router(), tenantA: tenantA, tenantB: tenantB, tokenA: "tok-a", creds: creds}
}

// A empresa-cliente registra a PRÓPRIA chave com o próprio token.
//
// Sem esta rota, quem provisionava credencial e certificado sozinho continuava
// travado: sem a chave, o adaptador não sabe para qual conta rotear os fundos.
func TestSelfServePixKeyWritesOwnTenant(t *testing.T) {
	t.Parallel()
	f := newPixKeyFixture(t, true)

	rec := do(t, f.handler, http.MethodPut, pixKeyPath, f.tokenA, nil,
		map[string]any{"creditor_key": "c7e43ff5-0000-0000-0000-000000000000"})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	cred, err := f.creds.GetBankCredential(context.Background(), f.tenantA, "c6")
	if err != nil {
		t.Fatalf("ler credencial: %v", err)
	}
	if cred.CreditorKey != "c7e43ff5-0000-0000-0000-000000000000" {
		t.Fatalf("chave não gravada no tenant do token, got %q", cred.CreditorKey)
	}
}

// A chave é dado de ROTEAMENTO DE FUNDOS: escreve-se, não se lê de volta. Ecoar
// transformaria a rota num jeito de descobrir para onde vai o dinheiro de um tenant.
func TestSelfServePixKeyNaoEcoaAChave(t *testing.T) {
	t.Parallel()
	f := newPixKeyFixture(t, true)
	const chave = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

	rec := do(t, f.handler, http.MethodPut, pixKeyPath, f.tokenA, nil,
		map[string]any{"creditor_key": chave})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, chave) {
		t.Fatalf("a resposta devolveu a chave: %s", body)
	}
}

// A01 por construção: não existe seletor de tenant no contrato, então o token só
// consegue escrever a própria chave. O tenant B não é tocado.
func TestSelfServePixKeyNaoAlcancaOutroTenant(t *testing.T) {
	t.Parallel()
	f := newPixKeyFixture(t, true)

	if rec := do(t, f.handler, http.MethodPut, pixKeyPath, f.tokenA, nil,
		map[string]any{"creditor_key": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "tenant_id": f.tenantB}); rec.Code == http.StatusOK {
		// Um campo desconhecido é recusado pelo decodificador estrito; se um dia
		// deixar de ser, o tenant B ainda assim não pode ter sido tocado.
		t.Log("corpo com tenant_id foi aceito; conferindo que não vazou")
	}

	cred, err := f.creds.GetBankCredential(context.Background(), f.tenantB, "c6")
	if err == nil && cred.CreditorKey != "" {
		t.Fatalf("chave do tenant B foi escrita por um token de outro tenant: %q", cred.CreditorKey)
	}
}

// Mesma trava das outras rotas self-serve: com a flag desligada a rota nem existe.
func TestSelfServePixKeyInerteComFlagDesligada(t *testing.T) {
	t.Parallel()
	f := newPixKeyFixture(t, false)

	rec := do(t, f.handler, http.MethodPut, pixKeyPath, f.tokenA, nil,
		map[string]any{"creditor_key": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"})
	if rec.Code == http.StatusOK {
		t.Fatalf("rota respondeu 200 com a flag desligada")
	}
}
