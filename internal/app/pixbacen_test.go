package app_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fakeBacen é o banco das superfícies BACEN novas. Ele não é o stub compartilhado de
// propósito: o stub NÃO implementa estas portas, e é exatamente isso que faz o
// roteador falhar fechado para um banco que não as fala. Um fake local prova o
// serviço sem apagar essa prova.
type fakeBacen struct {
	// gravado registra a última chamada, para o teste conferir o que o serviço
	// realmente mandou ao banco e não só o que ele devolveu.
	txID       string
	req        ports.ChargeRequest
	expiresIn  time.Duration
	cobvReq    ports.PixDueChargeRequest
	locTipo    string
	locID      int64
	e2e        string
	refundID   string
	refundReq  ports.PixRefundRequest
	batchID    string
	batchDesc  string
	batchReqs  []ports.PixDueChargeRequest
	batchRev   bool
	pixFilter  ports.PixListFilter
	locFilter  ports.PixLocationFilter
	recvFilter ports.ReceivedPixFilter

	err error
}

func (f *fakeBacen) CreateImmediateChargeAutoTxID(_ context.Context, _ string, req ports.ChargeRequest, d time.Duration) (ports.PixChargeResult, error) {
	f.req, f.expiresIn = req, d
	return ports.PixChargeResult{TxID: "auto"}, f.err
}

func (f *fakeBacen) ReviseImmediateCharge(_ context.Context, _, txID string, req ports.ChargeRequest, d time.Duration) (ports.PixChargeResult, error) {
	f.txID, f.req, f.expiresIn = txID, req, d
	return ports.PixChargeResult{TxID: txID}, f.err
}

func (f *fakeBacen) ReviseDueCharge(_ context.Context, _, txID string, req ports.PixDueChargeRequest) (ports.PixDueChargeResult, error) {
	f.txID, f.cobvReq = txID, req
	return ports.PixDueChargeResult{TxID: txID}, f.err
}

func (f *fakeBacen) ListDueCharges(_ context.Context, _ string, filter ports.PixListFilter) (ports.PixDueChargeList, error) {
	f.pixFilter = filter
	return ports.PixDueChargeList{Charges: []ports.PixDueChargeResult{{TxID: "t1"}}}, f.err
}

func (f *fakeBacen) CreateLocation(_ context.Context, _, tipoCob string) (ports.PixLocation, error) {
	f.locTipo = tipoCob
	return ports.PixLocation{ID: 7, TipoCob: tipoCob}, f.err
}

func (f *fakeBacen) ListLocations(_ context.Context, _ string, filter ports.PixLocationFilter) (ports.PixLocationList, error) {
	f.locFilter = filter
	return ports.PixLocationList{Locations: []ports.PixLocation{{ID: 7}}}, f.err
}

func (f *fakeBacen) GetLocation(_ context.Context, _ string, id int64) (ports.PixLocation, error) {
	f.locID = id
	return ports.PixLocation{ID: id, TxID: "vinculado"}, f.err
}

func (f *fakeBacen) UnlinkLocationTxID(_ context.Context, _ string, id int64) (ports.PixLocation, error) {
	f.locID = id
	return ports.PixLocation{ID: id}, f.err
}

func (f *fakeBacen) GetReceivedPix(_ context.Context, _, e2e string) (ports.ReceivedPix, error) {
	f.e2e = e2e
	return ports.ReceivedPix{EndToEndID: e2e, AmountCents: 5000}, f.err
}

func (f *fakeBacen) ListReceivedPix(_ context.Context, _ string, filter ports.ReceivedPixFilter) (ports.ReceivedPixList, error) {
	f.recvFilter = filter
	return ports.ReceivedPixList{Received: []ports.ReceivedPix{{EndToEndID: "E1"}}}, f.err
}

func (f *fakeBacen) RequestRefund(_ context.Context, _, e2e, refundID string, req ports.PixRefundRequest) (ports.PixRefund, error) {
	f.e2e, f.refundID, f.refundReq = e2e, refundID, req
	return ports.PixRefund{ID: refundID, AmountCents: req.AmountCents, Status: "EM_PROCESSAMENTO"}, f.err
}

func (f *fakeBacen) GetRefund(_ context.Context, _, e2e, refundID string) (ports.PixRefund, error) {
	f.e2e, f.refundID = e2e, refundID
	return ports.PixRefund{ID: refundID, Status: "DEVOLVIDO"}, f.err
}

func (f *fakeBacen) CreateBatch(_ context.Context, _, batchID, desc string, charges []ports.PixDueChargeRequest) error {
	f.batchID, f.batchDesc, f.batchReqs, f.batchRev = batchID, desc, charges, false
	return f.err
}

func (f *fakeBacen) ReviseBatch(_ context.Context, _, batchID, desc string, charges []ports.PixDueChargeRequest) error {
	f.batchID, f.batchDesc, f.batchReqs, f.batchRev = batchID, desc, charges, true
	return f.err
}

func (f *fakeBacen) GetBatch(_ context.Context, _, batchID string) (ports.PixDueChargeBatch, error) {
	f.batchID = batchID
	return ports.PixDueChargeBatch{ID: batchID}, f.err
}

func (f *fakeBacen) ListBatches(_ context.Context, _ string, _ ports.PixDueChargeBatchFilter) (ports.PixDueChargeBatchList, error) {
	return ports.PixDueChargeBatchList{Batches: []ports.PixDueChargeBatch{{ID: "L1"}}}, f.err
}

// newBacenHarness sobe um tenant ativo com credencial e liga o fake em todas as portas
// novas de uma vez.
func newBacenHarness(t *testing.T) (*harness, *fakeBacen, string) {
	t.Helper()
	h := newHarness(t)
	fake := &fakeBacen{}
	h.deps.PixDueCharge = h.bank
	h.deps.PixChargeReviser = fake
	h.deps.PixDueChargeReviser = fake
	h.deps.PixDueChargeLister = fake
	h.deps.PixLocation = fake
	h.deps.PixReceived = fake
	h.deps.PixDueChargeBatch = fake
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	return h, fake, tn.ID()
}

// janela devolve um intervalo válido para as listagens.
func janela() (time.Time, time.Time) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return start, start.Add(24 * time.Hour)
}

func TestReviseImmediateCharge(t *testing.T) {
	t.Parallel()
	h, fake, tenantID := newBacenHarness(t)
	svc := app.NewPixService(h.deps)
	ctx := context.Background()

	res, err := svc.ReviseImmediateCharge(ctx, app.ReviseImmediateChargeInput{
		TenantID: tenantID, TxID: "tx1", AmountCents: 2500,
	})
	if err != nil {
		t.Fatalf("revise: %v", err)
	}
	if res.TxID != "tx1" || fake.txID != "tx1" || fake.req.AmountCents != 2500 {
		t.Fatalf("revisão não chegou ao banco: %+v / %+v", res, fake.req)
	}

	// Uma revisão que não mudaria nada é campo perdido: responder "ok" a ela
	// relataria uma alteração que não aconteceu.
	if _, err := svc.ReviseImmediateCharge(ctx, app.ReviseImmediateChargeInput{
		TenantID: tenantID, TxID: "tx1",
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("revisão vazia deve ser recusada, veio %v", err)
	}
	// Valor negativo é recusado antes do banco: é operação de dinheiro.
	if _, err := svc.ReviseImmediateCharge(ctx, app.ReviseImmediateChargeInput{
		TenantID: tenantID, TxID: "tx1", AmountCents: -1,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("valor negativo deve ser recusado, veio %v", err)
	}
	if _, err := svc.ReviseImmediateCharge(ctx, app.ReviseImmediateChargeInput{
		TenantID: tenantID, AmountCents: 100,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("txid vazio deve ser recusado, veio %v", err)
	}
	// Tenant desconhecido nunca chega ao banco.
	if _, err := svc.ReviseImmediateCharge(ctx, app.ReviseImmediateChargeInput{
		TenantID: "missing", TxID: "tx1", AmountCents: 100,
	}); err == nil {
		t.Fatal("tenant desconhecido deve falhar")
	}
}

// Sem a porta ligada o serviço responde indisponível — nunca em pânico, e nunca
// fingindo sucesso.
func TestBacenSurfacesUnavailableWithoutPort(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ctx := context.Background()
	if _, err := app.NewPixService(h.deps).ReviseImmediateCharge(ctx,
		app.ReviseImmediateChargeInput{TenantID: "t1", TxID: "x", AmountCents: 1}); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
	if _, err := app.NewPixLocationService(h.deps).CreateLocation(ctx, "t1", "cob"); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
	if _, err := app.NewPixReceivedService(h.deps).GetReceivedPix(ctx, "t1", "E1"); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
	if err := app.NewPixBatchService(h.deps).CreateBatch(ctx, app.BatchInput{TenantID: "t1"}); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
	if _, err := app.NewAcquirerStatementService(h.deps).ListReceivables(ctx,
		app.AcquirerStatementInput{TenantID: "t1"}); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
	if _, err := app.NewPlainBoletoService(h.deps).GetPlainBoleto(ctx, "t1", "s1"); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want unavailable, got %v", err)
	}
}

func TestReviseAndListDueCharges(t *testing.T) {
	t.Parallel()
	h, fake, tenantID := newBacenHarness(t)
	svc := app.NewPixDueChargeService(h.deps)
	ctx := context.Background()

	in := cobvInput(tenantID)
	if _, err := svc.ReviseDueCharge(ctx, tenantID, "tx9", in); err != nil {
		t.Fatalf("revise cobv: %v", err)
	}
	// A revisão endereça a cobrança pelo txid do CAMINHO, não por um do corpo.
	if fake.txID != "tx9" || fake.cobvReq.TxID != "tx9" {
		t.Fatalf("txid não propagou: %q / %+v", fake.txID, fake.cobvReq)
	}
	if _, err := svc.ReviseDueCharge(ctx, tenantID, "  ", in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("txid vazio deve ser recusado, veio %v", err)
	}

	start, end := janela()
	list, err := svc.ListDueCharges(ctx, app.ListDueChargesInput{TenantID: tenantID, Start: start, End: end})
	if err != nil {
		t.Fatalf("list cobv: %v", err)
	}
	if len(list.Charges) != 1 || !fake.pixFilter.Start.Equal(start) {
		t.Fatalf("janela não propagou: %+v", fake.pixFilter)
	}
	// Janela invertida é recusada aqui, e não vira um 400 opaco do PSP.
	if _, err := svc.ListDueCharges(ctx, app.ListDueChargesInput{
		TenantID: tenantID, Start: end, End: start,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("janela invertida deve ser recusada, veio %v", err)
	}
}

func TestPixLocationLifecycle(t *testing.T) {
	t.Parallel()
	h, fake, tenantID := newBacenHarness(t)
	svc := app.NewPixLocationService(h.deps)
	ctx := context.Background()

	loc, err := svc.CreateLocation(ctx, tenantID, "COBV")
	if err != nil {
		t.Fatalf("create loc: %v", err)
	}
	// O tipo é normalizado para minúsculo antes de ir ao banco.
	if loc.ID != 7 || fake.locTipo != "cobv" {
		t.Fatalf("tipo não normalizado: %q", fake.locTipo)
	}
	if _, err := svc.CreateLocation(ctx, tenantID, "qr"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tipo desconhecido deve ser recusado, veio %v", err)
	}

	if _, err := svc.GetLocation(ctx, tenantID, 0); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("id zero deve ser recusado, veio %v", err)
	}
	if _, err := svc.UnlinkLocationTxID(ctx, tenantID, -3); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("id negativo deve ser recusado, veio %v", err)
	}
	got, err := svc.UnlinkLocationTxID(ctx, tenantID, 7)
	if err != nil {
		t.Fatalf("unlink: %v", err)
	}
	// Desvincular deixa a location sem txid — e não cancela cobrança nenhuma.
	if got.TxID != "" || fake.locID != 7 {
		t.Fatalf("unlink não limpou o vínculo: %+v", got)
	}

	start, end := janela()
	if _, err := svc.ListLocations(ctx, app.ListLocationsInput{
		TenantID: tenantID, Start: start, End: end, TipoCob: "COB",
	}); err != nil {
		t.Fatalf("list loc: %v", err)
	}
	if fake.locFilter.TipoCob != "cob" {
		t.Fatalf("filtro não normalizado: %+v", fake.locFilter)
	}
	if _, err := svc.ListLocations(ctx, app.ListLocationsInput{
		TenantID: tenantID, Start: start, End: end, TipoCob: "boleto",
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tipo desconhecido no filtro deve ser recusado, veio %v", err)
	}
}

func TestReceivedPixAndRefund(t *testing.T) {
	t.Parallel()
	h, fake, tenantID := newBacenHarness(t)
	svc := app.NewPixReceivedService(h.deps)
	ctx := context.Background()

	if _, err := svc.GetReceivedPix(ctx, tenantID, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("e2eid vazio deve ser recusado, veio %v", err)
	}
	if _, err := svc.GetReceivedPix(ctx, tenantID, "E1"); err != nil {
		t.Fatalf("get: %v", err)
	}

	ref, err := svc.RequestRefund(ctx, app.RequestRefundInput{
		TenantID: tenantID, EndToEndID: "E1", RefundID: "d1", AmountCents: 1000, Nature: "original",
	})
	if err != nil {
		t.Fatalf("refund: %v", err)
	}
	// A natureza é normalizada; o id da devolução é o de QUEM CHAMA, e é ele que
	// torna um reenvio a MESMA devolução em vez de uma segunda.
	if ref.ID != "d1" || fake.refundID != "d1" || fake.refundReq.Nature != ports.RefundOriginal {
		t.Fatalf("devolução não propagou: %+v / %+v", ref, fake.refundReq)
	}
	for _, caso := range []struct {
		nome string
		in   app.RequestRefundInput
	}{
		{"sem id", app.RequestRefundInput{TenantID: tenantID, EndToEndID: "E1", AmountCents: 100}},
		{"sem e2e", app.RequestRefundInput{TenantID: tenantID, RefundID: "d1", AmountCents: 100}},
		{"valor zero", app.RequestRefundInput{TenantID: tenantID, EndToEndID: "E1", RefundID: "d1"}},
		{"valor negativo", app.RequestRefundInput{TenantID: tenantID, EndToEndID: "E1", RefundID: "d1", AmountCents: -5}},
		{"natureza inválida", app.RequestRefundInput{TenantID: tenantID, EndToEndID: "E1", RefundID: "d1", AmountCents: 100, Nature: "porque sim"}},
	} {
		if _, err := svc.RequestRefund(ctx, caso.in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: queria validação, veio %v", caso.nome, err)
		}
	}

	if _, err := svc.GetRefund(ctx, tenantID, "E1", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("refund id vazio deve ser recusado, veio %v", err)
	}

	start, end := janela()
	if _, err := svc.ListReceivedPix(ctx, app.ListReceivedPixInput{
		TenantID: tenantID, Start: start, End: end, PayerTaxID: "12345678901",
	}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if fake.recvFilter.PayerTaxID != "12345678901" {
		t.Fatalf("filtro do pagador não propagou: %+v", fake.recvFilter)
	}
	// Um documento que não é CPF nem CNPJ é recusado aqui: mandá-lo ao PSP
	// devolveria lista vazia, que se lê como "não houve PIX".
	if _, err := svc.ListReceivedPix(ctx, app.ListReceivedPixInput{
		TenantID: tenantID, Start: start, End: end, PayerTaxID: "123",
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("documento torto deve ser recusado, veio %v", err)
	}
}

func TestPixBatchWrites(t *testing.T) {
	t.Parallel()
	h, fake, tenantID := newBacenHarness(t)
	svc := app.NewPixBatchService(h.deps)
	ctx := context.Background()

	carga := func(txids ...string) []app.BatchChargeInput {
		out := make([]app.BatchChargeInput, len(txids))
		for i, tx := range txids {
			out[i] = app.BatchChargeInput{TxID: tx, DueChargeInput: cobvInput(tenantID)}
		}
		return out
	}

	if err := svc.CreateBatch(ctx, app.BatchInput{
		TenantID: tenantID, BatchID: "L1", Description: "mensalidades",
		Charges: carga("tx1", "tx2"),
	}); err != nil {
		t.Fatalf("create batch: %v", err)
	}
	if fake.batchID != "L1" || len(fake.batchReqs) != 2 || fake.batchRev {
		t.Fatalf("lote não propagou: %+v", fake)
	}
	// Cada cobrança do lote é endereçada pelo SEU txid, não por um do lote.
	if fake.batchReqs[0].TxID != "tx1" || fake.batchReqs[1].TxID != "tx2" {
		t.Fatalf("txid por cobrança não propagou: %+v", fake.batchReqs)
	}

	if err := svc.ReviseBatch(ctx, app.BatchInput{
		TenantID: tenantID, BatchID: "L1", Description: "mensalidades",
		Charges: carga("tx1"),
	}); err != nil {
		t.Fatalf("revise batch: %v", err)
	}
	if !fake.batchRev {
		t.Fatal("revisão deve usar o verbo de revisão, não o de criação")
	}

	for _, caso := range []struct {
		nome string
		in   app.BatchInput
	}{
		{"sem id", app.BatchInput{TenantID: tenantID, Description: "x", Charges: carga("tx1")}},
		{"sem descrição", app.BatchInput{TenantID: tenantID, BatchID: "L1", Charges: carga("tx1")}},
		{"sem cobrança", app.BatchInput{TenantID: tenantID, BatchID: "L1", Description: "x"}},
		{"cobrança sem txid", app.BatchInput{TenantID: tenantID, BatchID: "L1", Description: "x", Charges: carga("")}},
	} {
		if err := svc.CreateBatch(ctx, caso.in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: queria validação, veio %v", caso.nome, err)
		}
	}

	// O teto existe para um corpo grande não virar um lote arbitrariamente grande no
	// PSP. 201 txids distintos passam de 200.
	muitos := make([]string, 201)
	for i := range muitos {
		muitos[i] = "tx" + strconv.Itoa(i)
	}
	if err := svc.CreateBatch(ctx, app.BatchInput{
		TenantID: tenantID, BatchID: "L1", Description: "x", Charges: carga(muitos...),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("lote acima do teto deve ser recusado, veio %v", err)
	}

	// Uma cobrança inválida derruba o lote INTEIRO: meio lote registrado é pior do
	// que nenhum, porque ninguém sabe qual metade entrou.
	ruim := carga("tx1", "tx2")
	ruim[1].AmountCents = -1
	if err := svc.CreateBatch(ctx, app.BatchInput{
		TenantID: tenantID, BatchID: "L1", Description: "x", Charges: ruim,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cobrança inválida deve derrubar o lote, veio %v", err)
	}

	if _, err := svc.GetBatch(ctx, tenantID, " "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("id vazio deve ser recusado, veio %v", err)
	}
	start, end := janela()
	if _, err := svc.ListBatches(ctx, app.ListBatchesInput{TenantID: tenantID, Start: start, End: end}); err != nil {
		t.Fatalf("list batches: %v", err)
	}
}
