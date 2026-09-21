package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fakeSlips é o banco do boleto simples e da listagem do BolePix, e do extrato de
// adquirência. Como o fake das superfícies BACEN, ele existe porque o stub
// compartilhado NÃO fala estas portas — e é essa ausência que faz o roteador falhar
// fechado para um banco que não as tem.
type fakeSlips struct {
	req        ports.BoletoRequest
	patch      ports.BoletoPatch
	slipID     string
	canceled   string
	listFilter ports.BoletoListFilter
	acqFilter  ports.AcquirerStatementFilter
	err        error
}

func (f *fakeSlips) CreatePlainBoleto(_ context.Context, _ string, req ports.BoletoRequest) (ports.BoletoResult, error) {
	f.req = req
	return ports.BoletoResult{BoletoID: "slip-1", AmountCents: req.AmountCents}, f.err
}

func (f *fakeSlips) GetPlainBoleto(_ context.Context, _, slipID string) (ports.BoletoResult, error) {
	f.slipID = slipID
	return ports.BoletoResult{BoletoID: slipID, AmountCents: 1000}, f.err
}

func (f *fakeSlips) UpdatePlainBoleto(_ context.Context, _, slipID string, patch ports.BoletoPatch) (ports.BoletoResult, error) {
	f.slipID, f.patch = slipID, patch
	return ports.BoletoResult{BoletoID: slipID}, f.err
}

func (f *fakeSlips) CancelPlainBoleto(_ context.Context, _, slipID string) error {
	f.canceled = slipID
	return f.err
}

func (f *fakeSlips) GetPlainBoletoPDF(_ context.Context, _, slipID string) (ports.BoletoDocument, error) {
	f.slipID = slipID
	return ports.BoletoDocument{Content: []byte("%PDF-1.4"), ContentType: "application/pdf", Filename: "b.pdf"}, f.err
}

func (f *fakeSlips) ListBoletos(_ context.Context, _ string, filter ports.BoletoListFilter) (ports.BoletoList, error) {
	f.listFilter = filter
	return ports.BoletoList{Boletos: []ports.BoletoResult{{BoletoID: "b1"}}, TotalItems: 1}, f.err
}

func (f *fakeSlips) ListReceivables(_ context.Context, _ string, filter ports.AcquirerStatementFilter) (ports.ReceivableList, error) {
	f.acqFilter = filter
	return ports.ReceivableList{Receivables: []ports.Receivable{{ReceivableID: "r1", NetAmountCents: 2839}}}, f.err
}

func (f *fakeSlips) ListCardTransactions(_ context.Context, _ string, filter ports.AcquirerStatementFilter) (ports.CardTransactionList, error) {
	f.acqFilter = filter
	return ports.CardTransactionList{Transactions: []ports.CardTransaction{{ID: "t1", AmountCents: 3000}}}, f.err
}

func newSlipHarness(t *testing.T) (*harness, *fakeSlips, string) {
	t.Helper()
	h := newHarness(t)
	fake := &fakeSlips{}
	h.deps.PlainBoleto = fake
	h.deps.BoletoLister = fake
	h.deps.AcquirerStatement = fake
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	return h, fake, tn.ID()
}

func slipInput(tenantID string) app.PlainBoletoInput {
	return app.PlainBoletoInput{
		TenantID: tenantID, SlipID: "s1", AmountCents: 10000, Currency: "BRL",
		DueDate: time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		FineBps: 200, MonthlyInterestBps: 100,
		Payer: ports.BoletoPayer{
			Name: "Maria", TaxID: "12345678901",
			Address: ports.BoletoAddress{
				Street: "Rua das Flores", Number: 123,
				City: "Brasília", State: "DF", ZipCode: "70000000",
			},
		},
		IdempotencyKey: "k1",
	}
}

func TestPlainBoletoCreate(t *testing.T) {
	t.Parallel()
	h, fake, tenantID := newSlipHarness(t)
	svc := app.NewPlainBoletoService(h.deps)
	ctx := context.Background()

	res, err := svc.CreatePlainBoleto(ctx, slipInput(tenantID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.BoletoID != "slip-1" || fake.req.AmountCents != 10000 {
		t.Fatalf("emissão não propagou: %+v / %+v", res, fake.req)
	}

	// Multa é percentual OU valor fixo: o banco carrega UM valor com UM tipo, e
	// mandar os dois não tem tradução certa.
	dois := slipInput(tenantID)
	dois.FineFixedCents = 500
	if _, err := svc.CreatePlainBoleto(ctx, dois); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("multa dupla deve ser recusada, veio %v", err)
	}

	semID := slipInput(tenantID)
	semID.SlipID = "  "
	if _, err := svc.CreatePlainBoleto(ctx, semID); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("slip id vazio deve ser recusado, veio %v", err)
	}

	semData := slipInput(tenantID)
	semData.DueDate = time.Time{}
	if _, err := svc.CreatePlainBoleto(ctx, semData); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("vencimento vazio deve ser recusado, veio %v", err)
	}
}

// As três faixas de desconto são a capacidade que só este produto tem — e a razão de
// ele não ser o BolePix com outro nome.
func TestPlainBoletoDiscountTiers(t *testing.T) {
	t.Parallel()
	h, _, tenantID := newSlipHarness(t)
	svc := app.NewPlainBoletoService(h.deps)
	ctx := context.Background()

	ok := slipInput(tenantID)
	ok.Discounts = []ports.BoletoDiscountTier{
		{DaysBeforeDue: 10, Bps: 500}, {DaysBeforeDue: 5, Bps: 300}, {DaysBeforeDue: 1, Bps: 100},
	}
	if _, err := svc.CreatePlainBoleto(ctx, ok); err != nil {
		t.Fatalf("três faixas devem ser aceitas: %v", err)
	}

	for _, caso := range []struct {
		nome   string
		tiers  []ports.BoletoDiscountTier
		porque string
	}{
		{"quatro faixas", []ports.BoletoDiscountTier{
			{DaysBeforeDue: 20, Bps: 700}, {DaysBeforeDue: 10, Bps: 500},
			{DaysBeforeDue: 5, Bps: 300}, {DaysBeforeDue: 1, Bps: 100},
		}, "o produto carrega três"},
		{"formas misturadas", []ports.BoletoDiscountTier{
			{DaysBeforeDue: 10, Bps: 500}, {DaysBeforeDue: 5, FixedCents: 300},
		}, "o banco carrega um discount_type para o escalonamento inteiro"},
		{"prazos não decrescentes", []ports.BoletoDiscountTier{
			{DaysBeforeDue: 5, Bps: 500}, {DaysBeforeDue: 5, Bps: 300},
		}, "duas faixas no mesmo dia não têm ordem"},
		{"faixa nas duas formas", []ports.BoletoDiscountTier{
			{DaysBeforeDue: 5, Bps: 500, FixedCents: 300},
		}, "uma faixa é percentual ou valor"},
		{"faixa que não vale nada", []ports.BoletoDiscountTier{
			{DaysBeforeDue: 5},
		}, "desconto de zero não é desconto"},
		{"prazo negativo", []ports.BoletoDiscountTier{
			{DaysBeforeDue: -1, Bps: 500},
		}, "não existe antecipação para depois do vencimento"},
	} {
		in := slipInput(tenantID)
		in.Discounts = caso.tiers
		if _, err := svc.CreatePlainBoleto(ctx, in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s (%s): queria validação, veio %v", caso.nome, caso.porque, err)
		}
	}
}

func TestPlainBoletoUpdateCancelPDF(t *testing.T) {
	t.Parallel()
	h, fake, tenantID := newSlipHarness(t)
	svc := app.NewPlainBoletoService(h.deps)
	ctx := context.Background()
	cents := func(v int64) *int64 { return &v }

	if _, err := svc.UpdatePlainBoleto(ctx, tenantID, "s1", app.PlainBoletoPatchInput{
		AmountCents: cents(20000),
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if fake.patch.AmountCents == nil || *fake.patch.AmountCents != 20000 {
		t.Fatalf("valor não propagou: %+v", fake.patch)
	}
	// Alteração que não tocaria em nada é campo perdido, não um no-op bem-sucedido.
	if _, err := svc.UpdatePlainBoleto(ctx, tenantID, "s1", app.PlainBoletoPatchInput{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("patch vazio deve ser recusado, veio %v", err)
	}
	// Zero mandado como "sem mudança" pediria ao banco uma cobrança gratuita.
	if _, err := svc.UpdatePlainBoleto(ctx, tenantID, "s1", app.PlainBoletoPatchInput{
		AmountCents: cents(0),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("valor zero deve ser recusado, veio %v", err)
	}
	// Tocar num encargo monta o quadro COMPLETO, porque o banco substitui o objeto
	// inteiro em vez de mesclar nele.
	if _, err := svc.UpdatePlainBoleto(ctx, tenantID, "s1", app.PlainBoletoPatchInput{
		MonthlyInterestBps: cents(150),
	}); err != nil {
		t.Fatalf("update encargo: %v", err)
	}
	if fake.patch.Fees == nil || fake.patch.Fees.MonthlyInterestBps != 150 {
		t.Fatalf("encargo não virou quadro completo: %+v", fake.patch.Fees)
	}
	if _, err := svc.UpdatePlainBoleto(ctx, tenantID, "s1", app.PlainBoletoPatchInput{
		FineBps: cents(200), FineFixedCents: cents(500),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("multa dupla no patch deve ser recusada, veio %v", err)
	}

	if err := svc.CancelPlainBoleto(ctx, tenantID, "s1"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if fake.canceled != "s1" {
		t.Fatalf("baixa não propagou: %q", fake.canceled)
	}
	if err := svc.CancelPlainBoleto(ctx, tenantID, " "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("id vazio deve ser recusado, veio %v", err)
	}

	doc, err := svc.GetPlainBoletoPDF(ctx, tenantID, "s1")
	if err != nil {
		t.Fatalf("pdf: %v", err)
	}
	if len(doc.Content) == 0 || doc.ContentType != "application/pdf" {
		t.Fatalf("documento vazio: %+v", doc)
	}
	if _, err := svc.GetPlainBoletoPDF(ctx, tenantID, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("id vazio deve ser recusado, veio %v", err)
	}
	if _, err := svc.GetPlainBoleto(ctx, tenantID, " "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("id vazio deve ser recusado, veio %v", err)
	}
}

func TestListBoletosWindows(t *testing.T) {
	t.Parallel()
	h, fake, tenantID := newSlipHarness(t)
	svc := app.NewBoletoService(h.deps)
	ctx := context.Background()
	de := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	list, err := svc.ListBoletos(ctx, app.ListBoletosInput{
		TenantID: tenantID, DueDateFrom: de, DueDateTo: de.Add(7 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Boletos) != 1 || !fake.listFilter.DueDateFrom.Equal(de) {
		t.Fatalf("janela não propagou: %+v", fake.listFilter)
	}

	// Sem intervalo nenhum o banco responderia alguma coisa — e não seria a janela
	// que ninguém pediu.
	if _, err := svc.ListBoletos(ctx, app.ListBoletosInput{TenantID: tenantID}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("sem janela deve ser recusado, veio %v", err)
	}
	// Meio intervalo é o mesmo problema com outra cara.
	if _, err := svc.ListBoletos(ctx, app.ListBoletosInput{
		TenantID: tenantID, PaymentDateFrom: de,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("intervalo meio-aberto deve ser recusado, veio %v", err)
	}
	if _, err := svc.ListBoletos(ctx, app.ListBoletosInput{
		TenantID: tenantID, CreditDateFrom: de, CreditDateTo: de.Add(365 * 24 * time.Hour),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("janela larga demais deve ser recusada, veio %v", err)
	}
}

func TestAcquirerStatement(t *testing.T) {
	t.Parallel()
	h, fake, tenantID := newSlipHarness(t)
	svc := app.NewAcquirerStatementService(h.deps)
	ctx := context.Background()
	de := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	// Recebível e transação são o MESMO dia e não o mesmo dinheiro: R$ 30,00
	// autorizados chegam como R$ 28,39, já descontados MDR e tarifa.
	rec, err := svc.ListReceivables(ctx, app.AcquirerStatementInput{TenantID: tenantID, Start: de})
	if err != nil {
		t.Fatalf("receivables: %v", err)
	}
	tx, err := svc.ListCardTransactions(ctx, app.AcquirerStatementInput{TenantID: tenantID, Start: de})
	if err != nil {
		t.Fatalf("transactions: %v", err)
	}
	if rec.Receivables[0].NetAmountCents >= tx.Transactions[0].AmountCents {
		t.Fatalf("o líquido do recebível não pode igualar o bruto autorizado: %d vs %d",
			rec.Receivables[0].NetAmountCents, tx.Transactions[0].AmountCents)
	}
	// End vazio é "o mesmo dia de Start", que é o padrão do próprio adquirente.
	if !fake.acqFilter.End.IsZero() {
		t.Fatalf("End vazio não deve ser preenchido por nós: %+v", fake.acqFilter)
	}

	for _, caso := range []struct {
		nome string
		in   app.AcquirerStatementInput
	}{
		{"sem início", app.AcquirerStatementInput{TenantID: tenantID}},
		{"fim antes do início", app.AcquirerStatementInput{TenantID: tenantID, Start: de, End: de.Add(-time.Hour)}},
		{"janela larga demais", app.AcquirerStatementInput{TenantID: tenantID, Start: de, End: de.Add(365 * 24 * time.Hour)}},
		{"página negativa", app.AcquirerStatementInput{TenantID: tenantID, Start: de, Page: -1}},
	} {
		if _, err := svc.ListReceivables(ctx, caso.in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: queria validação, veio %v", caso.nome, err)
		}
		if _, err := svc.ListCardTransactions(ctx, caso.in); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s (transações): queria validação, veio %v", caso.nome, err)
		}
	}
}
