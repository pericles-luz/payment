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

// bacenBank é o banco de teste das superfícies do roteiro v3.0. Ele grava o que
// recebeu para o teste conferir que o caminho, e não o corpo, é quem endereça as
// coisas.
type bacenBank struct {
	txID     string
	locID    int64
	e2e      string
	refundID string
	batchID  string
	revisou  bool
	filtro   ports.ReceivedPixFilter
}

func (b *bacenBank) CreateImmediateChargeAutoTxID(context.Context, string, ports.ChargeRequest, time.Duration) (ports.PixChargeResult, error) {
	return ports.PixChargeResult{TxID: "auto"}, nil
}

func (b *bacenBank) ReviseImmediateCharge(_ context.Context, _, txID string, req ports.ChargeRequest, _ time.Duration) (ports.PixChargeResult, error) {
	b.txID = txID
	return ports.PixChargeResult{TxID: txID, ExpectedAmountCents: req.AmountCents, Status: "ATIVA"}, nil
}

func (b *bacenBank) ReviseDueCharge(_ context.Context, _, txID string, req ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	b.txID = txID
	return ports.PixDueChargeResult{TxID: txID, ExpectedAmountCents: req.AmountCents, Status: "ATIVA"}, nil
}

func (b *bacenBank) ListDueCharges(context.Context, string, ports.PixListFilter) (ports.PixDueChargeList, error) {
	return ports.PixDueChargeList{Charges: []ports.PixDueChargeResult{{TxID: "tx1"}}, PixPage: ports.PixPage{TotalItems: 1}}, nil
}

func (b *bacenBank) CreateLocation(_ context.Context, _, tipoCob string) (ports.PixLocation, error) {
	return ports.PixLocation{ID: 42, TipoCob: tipoCob, Location: "pix.example/42"}, nil
}

func (b *bacenBank) ListLocations(context.Context, string, ports.PixLocationFilter) (ports.PixLocationList, error) {
	return ports.PixLocationList{Locations: []ports.PixLocation{{ID: 42}}}, nil
}

func (b *bacenBank) GetLocation(_ context.Context, _ string, id int64) (ports.PixLocation, error) {
	b.locID = id
	return ports.PixLocation{ID: id, TxID: "tx1"}, nil
}

func (b *bacenBank) UnlinkLocationTxID(_ context.Context, _ string, id int64) (ports.PixLocation, error) {
	b.locID = id
	return ports.PixLocation{ID: id}, nil
}

func (b *bacenBank) GetReceivedPix(_ context.Context, _, e2e string) (ports.ReceivedPix, error) {
	b.e2e = e2e
	// O banco devolve dado de pagador; a view não carrega nada disso.
	return ports.ReceivedPix{EndToEndID: e2e, AmountCents: 5000, PayerInfo: "ref 22"}, nil
}

func (b *bacenBank) ListReceivedPix(_ context.Context, _ string, f ports.ReceivedPixFilter) (ports.ReceivedPixList, error) {
	b.filtro = f
	return ports.ReceivedPixList{Received: []ports.ReceivedPix{{EndToEndID: "E1"}}}, nil
}

func (b *bacenBank) RequestRefund(_ context.Context, _, e2e, refundID string, req ports.PixRefundRequest) (ports.PixRefund, error) {
	b.e2e, b.refundID = e2e, refundID
	return ports.PixRefund{ID: refundID, AmountCents: req.AmountCents, Nature: req.Nature, Status: "EM_PROCESSAMENTO"}, nil
}

func (b *bacenBank) GetRefund(_ context.Context, _, e2e, refundID string) (ports.PixRefund, error) {
	b.e2e, b.refundID = e2e, refundID
	return ports.PixRefund{ID: refundID, Status: "DEVOLVIDO"}, nil
}

func (b *bacenBank) CreateBatch(_ context.Context, _, batchID, _ string, _ []ports.PixDueChargeRequest) error {
	b.batchID, b.revisou = batchID, false
	return nil
}

func (b *bacenBank) ReviseBatch(_ context.Context, _, batchID, _ string, _ []ports.PixDueChargeRequest) error {
	b.batchID, b.revisou = batchID, true
	return nil
}

func (b *bacenBank) GetBatch(_ context.Context, _, batchID string) (ports.PixDueChargeBatch, error) {
	b.batchID = batchID
	return ports.PixDueChargeBatch{ID: batchID, Description: "mensalidades", Items: []ports.PixDueChargeBatchItem{
		{TxID: "tx1", Status: string(ports.BatchChargeCreated)},
		{TxID: "tx2", Status: string(ports.BatchChargeDenied), Problem: "valor inválido"},
	}}, nil
}

func (b *bacenBank) ListBatches(context.Context, string, ports.PixDueChargeBatchFilter) (ports.PixDueChargeBatchList, error) {
	return ports.PixDueChargeBatchList{Batches: []ports.PixDueChargeBatch{{ID: "L1"}}}, nil
}

// newBacenFixture sobe o Router com as superfícies novas ligadas e DOIS tenants, para
// o isolamento entre eles poder ser exercitado.
func newBacenFixture(t *testing.T) (http.Handler, *bacenBank) {
	t.Helper()
	store := persistence.NewStore()
	creds := secret.NewStore(nil)
	stub := bank.NewStubProvider(creds)
	fake := &bacenBank{}
	deps := app.Deps{
		Payments: store, Tenants: store, Pricing: store, Ledger: store,
		Processed: store, Bus: inmemory.NewBus(), Bank: stub,
		Pix: stub, PixDueCharge: stub, Boleto: stub,
		PixChargeReviser: fake, PixDueChargeReviser: fake, PixDueChargeLister: fake,
		PixLocation: fake, PixReceived: fake, PixDueChargeBatch: fake,
		Credentials: creds, UoW: store,
		Clock: system.Clock{}, IDs: system.IDProvider{},
	}
	admin := app.NewAdminService(deps)
	seed := func(name, clientID string) string {
		tn, err := admin.CreateTenant(context.Background(), name)
		if err != nil {
			t.Fatalf("seed tenant %s: %v", name, err)
		}
		creds.Set(tn.ID(), ports.BankCredential{ClientID: clientID, Secret: "s"})
		return tn.ID()
	}
	idA := seed("Acme", "c6-acme")
	idB := seed("Beta", "c6-beta")
	auth := httpadapter.NewStaticTokenAuth(
		map[string]string{tenantToken: idA, tenantTokenB: idB}, []string{adminToken}, nil)
	srv := httpadapter.NewServer(httpadapter.Config{
		Charges:     app.NewChargeService(deps),
		Pix:         app.NewPixService(deps),
		PixCobV:     app.NewPixDueChargeService(deps),
		PixLocation: app.NewPixLocationService(deps),
		PixReceived: app.NewPixReceivedService(deps),
		PixBatch:    app.NewPixBatchService(deps),
		Admin:       admin,
		Webhooks:    app.NewWebhookService(deps),
		TenantAuth:  auth,
		AdminAuth:   auth,
	})
	return srv.Router(), fake
}

// janelaQS é uma janela válida em query string para as listagens.
func janelaQS() string {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return "?start=" + start.Format(time.RFC3339) + "&end=" + start.Add(24*time.Hour).Format(time.RFC3339)
}

// O segmento literal tem de vencer o {txid}: sem isso o chi engoliria "cobv", "loc",
// "received" e "lotecobv" como se fossem identificadores de cobrança, e a rota nova
// nunca seria alcançada. É a armadilha que a ordem de registro em server.go evita, e
// este teste é quem a prende.
func TestPixLiteralSegmentsBeatTxID(t *testing.T) {
	t.Parallel()
	handler, _ := newBacenFixture(t)

	for _, caso := range []struct{ nome, path string }{
		{"cobv", "/v1/pix/cobv" + janelaQS()},
		{"loc", "/v1/pix/loc" + janelaQS()},
		{"received", "/v1/pix/received" + janelaQS()},
		{"lotecobv", "/v1/pix/lotecobv" + janelaQS()},
	} {
		rec := do(t, handler, http.MethodGet, caso.path, tenantToken, nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: queria 200, veio %d body %s", caso.nome, rec.Code, rec.Body.String())
		}
	}
}

func TestRevisePixHTTP(t *testing.T) {
	t.Parallel()
	handler, fake := newBacenFixture(t)

	rec := do(t, handler, http.MethodPatch, "/v1/pix/tx-9", tenantToken, idem("k1"),
		map[string]any{"amount_cents": 2500})
	if rec.Code != http.StatusOK {
		t.Fatalf("revise: %d body %s", rec.Code, rec.Body.String())
	}
	// O txid vem do CAMINHO, não do corpo.
	if fake.txID != "tx-9" {
		t.Fatalf("txid do caminho não chegou ao banco: %q", fake.txID)
	}
	if decodePix(t, rec)["amount_cents"].(float64) != 2500 {
		t.Fatalf("valor não voltou: %s", rec.Body.String())
	}

	// Escrita sem Idempotency-Key é recusada, como em toda escrita do plano.
	rec = do(t, handler, http.MethodPatch, "/v1/pix/tx-9", tenantToken, nil,
		map[string]any{"amount_cents": 2500})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sem chave de idempotência: queria 400, veio %d", rec.Code)
	}
	// Corpo com campo desconhecido é recusado (anti mass-assignment).
	rec = do(t, handler, http.MethodPatch, "/v1/pix/tx-9", tenantToken, idem("k2"),
		map[string]any{"amount_cents": 2500, "tenant_id": "outro"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("campo desconhecido: queria 400, veio %d", rec.Code)
	}
	// Sem credencial não há rota nenhuma.
	rec = do(t, handler, http.MethodPatch, "/v1/pix/tx-9", "", idem("k3"),
		map[string]any{"amount_cents": 2500})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sem auth: queria 401, veio %d", rec.Code)
	}
}

func TestPixLocHTTP(t *testing.T) {
	t.Parallel()
	handler, fake := newBacenFixture(t)

	rec := do(t, handler, http.MethodPost, "/v1/pix/loc", tenantToken, nil,
		map[string]any{"tipo_cob": "cobv"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create loc: %d body %s", rec.Code, rec.Body.String())
	}
	if decodePix(t, rec)["id"].(float64) != 42 {
		t.Fatalf("id não voltou: %s", rec.Body.String())
	}

	rec = do(t, handler, http.MethodDelete, "/v1/pix/loc/42/txid", tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("unlink: %d body %s", rec.Code, rec.Body.String())
	}
	// Desvincular deixa a location sem txid — e o campo some da resposta em vez de
	// voltar vazio, para ninguém ler "" como um txid.
	if _, presente := decodePix(t, rec)["txid"]; presente {
		t.Fatalf("txid deveria ter sumido: %s", rec.Body.String())
	}
	if fake.locID != 42 {
		t.Fatalf("id do caminho não chegou: %d", fake.locID)
	}

	// Id que não é número responde 400: a location é endereçada por um inteiro do
	// PSP, não por um identificador opaco nosso.
	rec = do(t, handler, http.MethodGet, "/v1/pix/loc/abc", tenantToken, nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("id torto: queria 400, veio %d", rec.Code)
	}
	// Tipo desconhecido é recusado antes do banco.
	rec = do(t, handler, http.MethodPost, "/v1/pix/loc", tenantToken, nil,
		map[string]any{"tipo_cob": "boleto"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tipo desconhecido: queria 400, veio %d", rec.Code)
	}
	// Listagem sem janela é recusada: sem ela o PSP responderia alguma coisa que
	// ninguém pediu.
	rec = do(t, handler, http.MethodGet, "/v1/pix/loc", tenantToken, nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sem janela: queria 400, veio %d", rec.Code)
	}
}

func TestReceivedPixHTTP(t *testing.T) {
	t.Parallel()
	handler, fake := newBacenFixture(t)

	rec := do(t, handler, http.MethodGet, "/v1/pix/received/E123", tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d body %s", rec.Code, rec.Body.String())
	}
	body := decodePix(t, rec)
	if body["end_to_end_id"] != "E123" || fake.e2e != "E123" {
		t.Fatalf("e2eid não propagou: %v", body)
	}
	// ADR-0008: a identidade do pagador não é carregada — nem para o cliente, nem
	// por dentro. Só a mensagem livre que ele mesmo escolheu mandar.
	for _, proibido := range []string{"payer_tax_id", "payer_name", "payer"} {
		if _, presente := body[proibido]; presente {
			t.Fatalf("view carregou %q: %v", proibido, body)
		}
	}

	rec = do(t, handler, http.MethodPut, "/v1/pix/received/E123/refunds/d1", tenantToken, nil,
		map[string]any{"amount_cents": 1000, "nature": "ORIGINAL"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("refund: %d body %s", rec.Code, rec.Body.String())
	}
	// O par (e2eid, refundID) vem do CAMINHO e é o que torna o reenvio idempotente —
	// por isso não há Idempotency-Key nesta rota.
	if fake.e2e != "E123" || fake.refundID != "d1" {
		t.Fatalf("par do caminho não propagou: %q/%q", fake.e2e, fake.refundID)
	}

	rec = do(t, handler, http.MethodGet, "/v1/pix/received/E123/refunds/d1", tenantToken, nil, nil)
	if rec.Code != http.StatusOK || decodePix(t, rec)["status"] != "DEVOLVIDO" {
		t.Fatalf("get refund: %d body %s", rec.Code, rec.Body.String())
	}

	// Devolução de valor zero é recusada: não existe, e uma negativa seria um
	// pagamento.
	rec = do(t, handler, http.MethodPut, "/v1/pix/received/E123/refunds/d2", tenantToken, nil,
		map[string]any{"amount_cents": 0})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("valor zero: queria 400, veio %d", rec.Code)
	}

	// txid_present ausente é "não filtre", que é diferente de "filtre pelos sem
	// cobrança". Um valor que não é booleano é erro, não um false silencioso.
	rec = do(t, handler, http.MethodGet, "/v1/pix/received"+janelaQS()+"&txid_present=talvez",
		tenantToken, nil, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("booleano torto: queria 400, veio %d", rec.Code)
	}
	rec = do(t, handler, http.MethodGet, "/v1/pix/received"+janelaQS()+"&refund_present=true",
		tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d body %s", rec.Code, rec.Body.String())
	}
	if fake.filtro.RefundPresent == nil || !*fake.filtro.RefundPresent {
		t.Fatalf("filtro booleano não propagou: %+v", fake.filtro)
	}
}

func TestPixBatchHTTP(t *testing.T) {
	t.Parallel()
	handler, fake := newBacenFixture(t)
	due := time.Now().Add(240 * time.Hour).UTC().Format(time.RFC3339)
	carga := func(txids ...string) map[string]any {
		charges := make([]map[string]any, len(txids))
		for i, tx := range txids {
			charges[i] = map[string]any{
				"txid": tx, "amount_cents": 10000, "currency": "BRL",
				"due_date": due, "validity_days": 5,
				"devedor": map[string]any{
					"tax_id": "12345678901", "name": "Maria",
					"street": "Rua das Flores, 123", "city": "Brasília",
					"state": "DF", "zip_code": "70000000",
				},
				"creditor_key": "acme@pix.example",
			}
		}
		return map[string]any{"description": "mensalidades", "charges": charges}
	}

	// 202, não 201: o PSP ACEITA o lote e o processa depois. As cobranças ainda não
	// existem, e por isso a resposta não traz lote nenhum.
	rec := do(t, handler, http.MethodPut, "/v1/pix/lotecobv/L1", tenantToken, idem("k1"), carga("tx1", "tx2"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create batch: queria 202, veio %d body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("202 não deve trazer corpo: %s", rec.Body.String())
	}
	if fake.batchID != "L1" || fake.revisou {
		t.Fatalf("lote não propagou: %+v", fake)
	}

	rec = do(t, handler, http.MethodPatch, "/v1/pix/lotecobv/L1", tenantToken, idem("k2"), carga("tx1"))
	if rec.Code != http.StatusAccepted || !fake.revisou {
		t.Fatalf("revise batch: %d, revisou=%v", rec.Code, fake.revisou)
	}

	// A leitura é o ÚNICO lugar onde o resultado por cobrança aparece — inclusive o
	// motivo de uma NEGADA.
	rec = do(t, handler, http.MethodGet, "/v1/pix/lotecobv/L1", tenantToken, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get batch: %d body %s", rec.Code, rec.Body.String())
	}
	var lote struct {
		ID      string `json:"id"`
		Charges []struct {
			TxID    string `json:"txid"`
			Status  string `json:"status"`
			Problem string `json:"problem"`
		} `json:"charges"`
	}
	if err := json.NewDecoder(rec.Result().Body).Decode(&lote); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(lote.Charges) != 2 || lote.Charges[1].Problem == "" {
		t.Fatalf("resultado por cobrança perdido: %+v", lote)
	}

	// Uma cobrança sem txid derruba o lote inteiro: ela sumiria em silêncio.
	semTx := carga("tx1", "")
	rec = do(t, handler, http.MethodPut, "/v1/pix/lotecobv/L2", tenantToken, idem("k3"), semTx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("cobrança sem txid: queria 400, veio %d body %s", rec.Code, rec.Body.String())
	}
	// Escrita sem Idempotency-Key é recusada.
	rec = do(t, handler, http.MethodPut, "/v1/pix/lotecobv/L1", tenantToken, nil, carga("tx1"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sem chave: queria 400, veio %d", rec.Code)
	}
}

// Toda rota nova exige credencial: nenhuma delas é pública.
func TestBacenRoutesRequireAuth(t *testing.T) {
	t.Parallel()
	handler, _ := newBacenFixture(t)

	for _, caso := range []struct{ metodo, path string }{
		{http.MethodPatch, "/v1/pix/tx1"},
		{http.MethodPatch, "/v1/pix/cobv/tx1"},
		{http.MethodGet, "/v1/pix/cobv"},
		{http.MethodPost, "/v1/pix/loc"},
		{http.MethodGet, "/v1/pix/loc"},
		{http.MethodGet, "/v1/pix/loc/1"},
		{http.MethodDelete, "/v1/pix/loc/1/txid"},
		{http.MethodGet, "/v1/pix/received"},
		{http.MethodGet, "/v1/pix/received/E1"},
		{http.MethodPut, "/v1/pix/received/E1/refunds/d1"},
		{http.MethodGet, "/v1/pix/received/E1/refunds/d1"},
		{http.MethodPut, "/v1/pix/lotecobv/L1"},
		{http.MethodPatch, "/v1/pix/lotecobv/L1"},
		{http.MethodGet, "/v1/pix/lotecobv/L1"},
		{http.MethodGet, "/v1/pix/lotecobv"},
	} {
		rec := do(t, handler, caso.metodo, caso.path, "", nil, map[string]any{})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: queria 401, veio %d", caso.metodo, caso.path, rec.Code)
		}
	}
}
