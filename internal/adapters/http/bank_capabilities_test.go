package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

const capabilitiesPath = "/v1/bank-capabilities"

// stubCapabilities answers with a scripted result per tenant.
type stubCapabilities struct {
	byTenant map[string]ports.BankCapabilities
	err      error
	asked    []string
}

func (s *stubCapabilities) BankCapabilities(_ context.Context, tenantID string) (ports.BankCapabilities, error) {
	s.asked = append(s.asked, tenantID)
	if s.err != nil {
		return ports.BankCapabilities{}, s.err
	}
	caps, ok := s.byTenant[tenantID]
	if !ok {
		return ports.BankCapabilities{}, shared.ErrNotFound
	}
	return caps, nil
}

type capsFixture struct {
	handler http.Handler
	tenantA string
	tenantB string
	caps    *stubCapabilities
}

func newCapsFixture(t *testing.T, caps *stubCapabilities) *capsFixture {
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
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{"tok-a": tenantA, "tok-b": tenantB}, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges: app.NewChargeService(deps), Admin: admin,
		Webhooks:   app.NewWebhookService(deps),
		TenantAuth: auth, AdminAuth: auth, WebhookAuth: auth,
		BankCapabilities: caps,
	})
	return &capsFixture{handler: srv.Router(), tenantA: tenantA, tenantB: tenantB, caps: caps}
}

func decodeCaps(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	return out
}

// O caso que motivou a rota: conta com PIX contratado e checkout NÃO.
//
// Sem isto, a loja oferecia o botão de cartão e o comprador só descobria o problema
// quando o C6 respondia 403 — com o cartão na mão. A tela de configuração precisa poder
// dizer isso antes.
func TestBankCapabilitiesReportsCardUnavailable(t *testing.T) {
	t.Parallel()
	f := newCapsFixture(t, &stubCapabilities{byTenant: map[string]ports.BankCapabilities{}})
	f.caps.byTenant[f.tenantA] = ports.BankCapabilities{PIX: true, Card: false}

	rec := do(t, f.handler, http.MethodGet, capabilitiesPath, "tok-a", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	got := decodeCaps(t, rec.Body.Bytes())
	if got["pix"] != true {
		t.Fatalf("pix deveria ser true: %v", got)
	}
	if got["card"] != false {
		t.Fatalf("card deveria ser false para conta sem o produto contratado: %v", got)
	}
	if got["configured"] != true {
		t.Fatalf("configured deveria ser true: a empresa TEM credencial: %v", got)
	}
}

// A01 por construção: o tenant vem do token, nunca do cliente. Cada token só enxerga a
// si mesmo — não há seletor no contrato para abusar.
func TestBankCapabilitiesAlwaysAsksTheAuthenticatedTenant(t *testing.T) {
	t.Parallel()
	f := newCapsFixture(t, &stubCapabilities{byTenant: map[string]ports.BankCapabilities{}})
	f.caps.byTenant[f.tenantA] = ports.BankCapabilities{PIX: true, Card: true}
	f.caps.byTenant[f.tenantB] = ports.BankCapabilities{}

	// Token de B, tentando apontar para A por todos os caminhos que um cliente controla.
	rec := do(t, f.handler, http.MethodGet, capabilitiesPath+"?tenant_id="+f.tenantA, "tok-b", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	for _, asked := range f.caps.asked {
		if asked != f.tenantB {
			t.Fatalf("a rota consultou o tenant %q com o token de B: o seletor do cliente\nnão pode influenciar de quem são as capacidades", asked)
		}
	}
	got := decodeCaps(t, rec.Body.Bytes())
	if got["card"] == true {
		t.Fatalf("B recebeu as capacidades de A: %v", got)
	}
}

// "Ainda não configurou" é estado legítimo da tela, não erro: responde 200 com
// configured=false, para a tela distinguir de "configurou mas a conta não contratou".
func TestBankCapabilitiesUnconfiguredTenantIsNotAnError(t *testing.T) {
	t.Parallel()
	f := newCapsFixture(t, &stubCapabilities{byTenant: map[string]ports.BankCapabilities{}})

	rec := do(t, f.handler, http.MethodGet, capabilitiesPath, "tok-a", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	got := decodeCaps(t, rec.Body.Bytes())
	if got["configured"] != false || got["pix"] != false || got["card"] != false {
		t.Fatalf("tenant sem credencial: %v", got)
	}
}

// Falha do banco não vira "pode": um erro de verdade sobe como erro, para a tela dizer
// "não consegui verificar" em vez de habilitar uma modalidade por engano.
func TestBankCapabilitiesBankFailureIsNotAPermission(t *testing.T) {
	t.Parallel()
	f := newCapsFixture(t, &stubCapabilities{err: errors.New("psp indisponível")})

	rec := do(t, f.handler, http.MethodGet, capabilitiesPath, "tok-a", nil, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("falha do PSP respondeu 200 (%s): a tela leria isso como capacidade\nresolvida e poderia habilitar o que o banco vai recusar", rec.Body.String())
	}
}

// Sem token não passa: a rota é do plano do tenant.
func TestBankCapabilitiesRequiresTenantToken(t *testing.T) {
	t.Parallel()
	f := newCapsFixture(t, &stubCapabilities{byTenant: map[string]ports.BankCapabilities{}})

	if rec := do(t, f.handler, http.MethodGet, capabilitiesPath, "", nil, nil); rec.Code == http.StatusOK {
		t.Fatalf("rota respondeu 200 sem token: %s", rec.Body.String())
	}
}
