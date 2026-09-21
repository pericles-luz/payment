package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	httpadapter "github.com/ia-dev-sindireceita/payment/internal/adapters/http"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// slipBank serve o boleto simples, a listagem do BolePix e o extrato de adquirência.
type slipBank struct {
	req        ports.BoletoRequest
	patch      ports.BoletoPatch
	slipID     string
	cancelado  string
	listFilter ports.BoletoListFilter
	acqFilter  ports.AcquirerStatementFilter
}

func (b *slipBank) CreatePlainBoleto(_ context.Context, _ string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	b.req = req
	return ports.BoletoResult{
		BoletoID: "slip-1", AmountCents: req.AmountCents, Status: "REGISTERED",
		Barcode: "00190000090123456789012345678901234567890123",
	}, nil
}

func (b *slipBank) GetPlainBoleto(_ context.Context, _, slipID string) (ports.BoletoResult, error) {
	b.slipID = slipID
	return ports.BoletoResult{BoletoID: slipID, AmountCents: 10000, Status: "REGISTERED"}, nil
}

func (b *slipBank) UpdatePlainBoleto(_ context.Context, _, slipID string, patch ports.BoletoPatch) (ports.BoletoResult, error) {
	b.slipID, b.patch = slipID, patch
	return ports.BoletoResult{BoletoID: slipID, AmountCents: 20000, Status: "REGISTERED"}, nil
}

func (b *slipBank) CancelPlainBoleto(_ context.Context, _, slipID string) error {
	b.cancelado = slipID
	return nil
}

func (b *slipBank) GetPlainBoletoPDF(_ context.Context, _, slipID string) (ports.BoletoDocument, error) {
	b.slipID = slipID
	return ports.BoletoDocument{
		Content: []byte("%PDF-1.4 fake"), ContentType: "application/pdf", Filename: "boleto.pdf",
	}, nil
}

func (b *slipBank) ListBoletos(_ context.Context, _ string, f ports.BoletoListFilter) (ports.BoletoList, error) {
	b.listFilter = f
	return ports.BoletoList{
		Boletos: []ports.BoletoResult{{BoletoID: "b1", AmountCents: 5000}}, TotalItems: 1, TotalPages: 1,
	}, nil
}

func (b *slipBank) ListReceivables(_ context.Context, _ string, f ports.AcquirerStatementFilter) (ports.ReceivableList, error) {
	b.acqFilter = f
	return ports.ReceivableList{
		Receivables: []ports.Receivable{{
			ReceivableID: "r1", GrossAmountCents: 3000,
			// Dedução chega NEGATIVA do adquirente e assim fica: inverter o sinal
			// esconderia a direção do dinheiro.
			FeeCents: -161, NetAmountCents: 2839, Installment: 1, Installments: 1,
		}},
		AcquirerPage: ports.AcquirerPage{Page: 1, LastPage: 1, Items: 1},
	}, nil
}

func (b *slipBank) ListCardTransactions(_ context.Context, _ string, f ports.AcquirerStatementFilter) (ports.CardTransactionList, error) {
	b.acqFilter = f
	return ports.CardTransactionList{
		Transactions: []ports.CardTransaction{{ID: "t1", AmountCents: 3000, Status: "APPROVED"}},
		AcquirerPage: ports.AcquirerPage{Page: 1, LastPage: 1, Items: 1},
	}, nil
}

func newSlipFixture(t *testing.T) (http.Handler, *slipBank) {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	fake := &slipBank{}
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store,
		Processed: store, Bus: inmemory.NewBus(), Bank: stub, Boleto: stub,
		PlainBoleto: fake, BoletoLister: fake, AcquirerStatement: fake,
		Credentials: creds, UoW: store,
		Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	creds.Set(tn.ID(), ports.BankCredential{ClientID: "c6-acme", Secret: "s"})
	auth := httpadapter.NewStaticTokenAuth(map[string]string{tenantToken: tn.ID()}, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:     app.NewChargeService(deps),
		Boleto:      app.NewBoletoService(deps),
		PlainBoleto: app.NewPlainBoletoService(deps),
		Acquirer:    app.NewAcquirerStatementService(deps),
		Admin:       admin,
		Webhooks:    app.NewWebhookService(deps),
		TenantAuth:  auth,
		AdminAuth:   auth,
	})
	return srv.Router(), fake
}

func slipBody() map[string]any {
	return map[string]any{
		"slip_id":              "s1",
		"amount_cents":         10000,
		"currency":             "BRL",
		"due_date":             time.Now().Add(240 * time.Hour).UTC().Format(time.RFC3339),
		"fine_bps":             200,
		"monthly_interest_bps": 100,
		"payer": map[string]any{
			"name": "Maria", "tax_id": "12345678901",
			"street": "Rua das Flores", "number": 123,
			"city": "Brasília", "state": "DF", "zip_code": "70000000",
		},
	}
}

// O boleto simples tem caminho PRÓPRIO, e não é uma modalidade do /v1/boletos: os dois
// produtos não se confundem num relatório, e o BolePix que já está em produção não
// muda de comportamento por causa deste.
func TestPlainBoletoLifecycleHTTP(t *testing.T) {
	t.Parallel()
	handler, fake := newSlipFixture(t)

	rec := do(t, handler, http.MethodPost, "/v1/bank-slips", tenantToken, idem("k1"), slipBody())
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d body %s", rec.Code, rec.Body.String())
	}
	body := decodePix(t, rec)
	if body["boleto_id"] != "slip-1" || body["amount_cents"].(float64) != 10000 {
		t.Fatalf("emissão não voltou: %v", body)
	}
	// O endereço deste produto tem rua e NÚMERO separados — é a forma dele, não a do
	// BolePix.
	if fake.req.Payer.Address.Number != 123 {
		t.Fatalf("número do endereço não propagou: %+v", fake.req.Payer.Address)
	}

	rec = do(t, handler, http.MethodGet, "/v1/bank-slips/slip-1", tenantToken, nil, nil)
	if rec.Code != http.StatusOK || fake.slipID != "slip-1" {
		t.Fatalf("get: %d body %s", rec.Code, rec.Body.String())
	}

	rec = do(t, handler, http.MethodPatch, "/v1/bank-slips/slip-1", tenantToken, idem("k2"),
		map[string]any{"amount_cents": 20000})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d body %s", rec.Code, rec.Body.String())
	}
	if fake.patch.AmountCents == nil || *fake.patch.AmountCents != 20000 {
		t.Fatalf("valor não propagou: %+v", fake.patch)
	}
	// Um campo ausente é "deixa como está", e não "zera": o patch não carrega os
	// encargos que ninguém mandou.
	if fake.patch.Fees != nil {
		t.Fatalf("patch inventou encargos: %+v", fake.patch.Fees)
	}

	// A baixa responde sem corpo, porque o contrato do banco responde sem corpo.
	rec = do(t, handler, http.MethodDelete, "/v1/bank-slips/slip-1", tenantToken, nil, nil)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("delete: %d body %s", rec.Code, rec.Body.String())
	}
	if fake.cancelado != "slip-1" {
		t.Fatalf("baixa não propagou: %q", fake.cancelado)
	}

	rec = do(t, handler, http.MethodGet, "/v1/bank-slips/slip-1/pdf", tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pdf: %d body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("content-type: %q", ct)
	}
	// O documento carrega PII do pagador: nenhum intermediário pode guardá-lo.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache-control: %q", cc)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("falta nosniff no documento")
	}
}

func TestPlainBoletoHTTPErrors(t *testing.T) {
	t.Parallel()
	handler, _ := newSlipFixture(t)

	// Escalonamento de três faixas é a capacidade deste produto, e ela passa.
	comDesconto := slipBody()
	comDesconto["discounts"] = []map[string]any{
		{"days_before_due": 10, "bps": 500},
		{"days_before_due": 5, "bps": 300},
		{"days_before_due": 1, "bps": 100},
	}
	if rec := do(t, handler, http.MethodPost, "/v1/bank-slips", tenantToken, idem("kd"), comDesconto); rec.Code != http.StatusCreated {
		t.Fatalf("três faixas: %d body %s", rec.Code, rec.Body.String())
	}

	for _, caso := range []struct {
		nome  string
		muda  func(map[string]any)
		token string
		chave string
		quer  int
	}{
		{"sem chave de idempotência", func(map[string]any) {}, tenantToken, "", http.StatusBadRequest},
		{"sem auth", func(map[string]any) {}, "", "k", http.StatusUnauthorized},
		{"vencimento torto", func(m map[string]any) { m["due_date"] = "ontem" }, tenantToken, "k", http.StatusBadRequest},
		{"multa dupla", func(m map[string]any) { m["fine_fixed_cents"] = 500 }, tenantToken, "k", http.StatusBadRequest},
		{"campo desconhecido", func(m map[string]any) { m["tenant_id"] = "outro" }, tenantToken, "k", http.StatusBadRequest},
		{"quatro faixas", func(m map[string]any) {
			m["discounts"] = []map[string]any{
				{"days_before_due": 20, "bps": 700}, {"days_before_due": 10, "bps": 500},
				{"days_before_due": 5, "bps": 300}, {"days_before_due": 1, "bps": 100},
			}
		}, tenantToken, "k", http.StatusBadRequest},
		{"formas misturadas", func(m map[string]any) {
			m["discounts"] = []map[string]any{
				{"days_before_due": 10, "bps": 500}, {"days_before_due": 5, "fixed_cents": 300},
			}
		}, tenantToken, "k", http.StatusBadRequest},
	} {
		corpo := slipBody()
		caso.muda(corpo)
		var headers map[string]string
		if caso.chave != "" {
			headers = idem(caso.chave + caso.nome)
		}
		rec := do(t, handler, http.MethodPost, "/v1/bank-slips", caso.token, headers, corpo)
		if rec.Code != caso.quer {
			t.Fatalf("%s: queria %d, veio %d body %s", caso.nome, caso.quer, rec.Code, rec.Body.String())
		}
	}
}

// A listagem do BolePix exige ao menos UMA janela — pagamento, vencimento ou crédito.
// São perguntas diferentes, e o banco as responde separadamente.
func TestListBoletosHTTP(t *testing.T) {
	t.Parallel()
	handler, fake := newSlipFixture(t)

	rec := do(t, handler, http.MethodGet, "/v1/boletos?due_date_from=2026-09-01&due_date_to=2026-09-30",
		tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d body %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Boletos    []map[string]any `json:"boletos"`
		TotalItems int              `json:"total_items"`
	}
	if err := json.NewDecoder(rec.Result().Body).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Boletos) != 1 || page.TotalItems != 1 {
		t.Fatalf("página perdida: %+v", page)
	}
	if fake.listFilter.DueDateFrom.IsZero() || !fake.listFilter.PaymentDateFrom.IsZero() {
		t.Fatalf("janela errada chegou ao banco: %+v", fake.listFilter)
	}

	for _, caso := range []struct{ nome, qs string }{
		{"sem janela", ""},
		{"meio intervalo", "?due_date_from=2026-09-01"},
		{"data torta", "?due_date_from=01/09/2026&due_date_to=2026-09-30"},
		{"janela larga demais", "?credit_date_from=2026-01-01&credit_date_to=2026-12-31"},
	} {
		rec := do(t, handler, http.MethodGet, "/v1/boletos"+caso.qs, tenantToken, nil, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: queria 400, veio %d body %s", caso.nome, rec.Code, rec.Body.String())
		}
	}

	// A listagem não pode ter engolido a leitura por id: "/boletos/{id}" continua
	// sendo outra rota.
	if rec := do(t, handler, http.MethodGet, "/v1/boletos/qualquer", tenantToken, nil, nil); rec.Code == http.StatusOK {
		t.Fatal("a listagem engoliu a leitura por id")
	}
}

func TestAcquirerStatementHTTP(t *testing.T) {
	t.Parallel()
	handler, fake := newSlipFixture(t)

	rec := do(t, handler, http.MethodGet, "/v1/acquirer/receivables?start_date=2026-09-01", tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("receivables: %d body %s", rec.Code, rec.Body.String())
	}
	var recebiveis struct {
		Receivables []struct {
			FeeCents       int64 `json:"fee_cents"`
			GrossCents     int64 `json:"gross_amount_cents"`
			NetAmountCents int64 `json:"net_amount_cents"`
		} `json:"receivables"`
		Items int `json:"items"`
	}
	if err := json.NewDecoder(rec.Result().Body).Decode(&recebiveis); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(recebiveis.Receivables) != 1 {
		t.Fatalf("página perdida: %+v", recebiveis)
	}
	// A dedução sai negativa como chegou, e o líquido é MENOR que o bruto: é essa
	// diferença que faz uma conciliação contra o nosso razão não fechar.
	r0 := recebiveis.Receivables[0]
	if r0.FeeCents >= 0 || r0.NetAmountCents >= r0.GrossCents {
		t.Fatalf("sinal ou líquido errado: %+v", r0)
	}
	// end_date ausente é o padrão do adquirente ("o mesmo dia"), não uma escolha
	// nossa: nada é preenchido por nós.
	if !fake.acqFilter.End.IsZero() {
		t.Fatalf("End foi inventado: %+v", fake.acqFilter)
	}

	rec = do(t, handler, http.MethodGet, "/v1/acquirer/transactions?start_date=2026-09-01&end_date=2026-09-02",
		tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("transactions: %d body %s", rec.Code, rec.Body.String())
	}
	// ADR-0008: a transação do adquirente traz nome do portador e PAN mascarado, e a
	// view não carrega nenhum dos dois.
	var transacoes struct {
		Transactions []map[string]any `json:"transactions"`
	}
	if err := json.NewDecoder(rec.Result().Body).Decode(&transacoes); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, proibido := range []string{"card_holder", "card_holder_name", "masked_pan", "pan"} {
		if _, presente := transacoes.Transactions[0][proibido]; presente {
			t.Fatalf("view carregou %q: %v", proibido, transacoes.Transactions[0])
		}
	}

	for _, caso := range []struct{ nome, qs string }{
		{"sem início", ""},
		{"data torta", "?start_date=01/09/2026"},
		{"fim antes do início", "?start_date=2026-09-10&end_date=2026-09-01"},
		{"janela larga demais", "?start_date=2026-01-01&end_date=2026-12-31"},
		{"página negativa", "?start_date=2026-09-01&page=-1"},
	} {
		for _, rota := range []string{"/v1/acquirer/receivables", "/v1/acquirer/transactions"} {
			rec := do(t, handler, http.MethodGet, rota+caso.qs, tenantToken, nil, nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s em %s: queria 400, veio %d body %s", caso.nome, rota, rec.Code, rec.Body.String())
			}
		}
	}

	for _, rota := range []string{"/v1/acquirer/receivables", "/v1/acquirer/transactions", "/v1/boletos"} {
		if rec := do(t, handler, http.MethodGet, rota, "", nil, nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s sem auth: queria 401, veio %d", rota, rec.Code)
		}
	}
}
