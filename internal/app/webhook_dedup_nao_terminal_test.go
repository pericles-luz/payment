package app_test

import (
	"context"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
)

// O aviso que chega ANTES de o PSP terminar de liquidar não pode queimar a chave de
// anti-replay. Este é o teste do incidente de 2026-08-20.
//
// O corpo do aviso PIX do C6 NÃO traz status (verificado no fio). A chave de evento
// degenera então para "<txid>|pix|" — idêntica em toda entrega sobre aquela cobrança.
// Enquanto "ainda não pago" era tratado como desfecho terminal, o primeiro aviso
// queimava a chave para sempre: a entrega seguinte, já com o pagamento concluído, era
// deduplicada como repetida e descartada. A cobrança ficava pendente, o dinheiro
// estava na conta, e nada em lugar nenhum dizia isso.
//
// Aconteceu exatamente assim em produção: PIX recebido às 12:33:23, aviso às 12:33:26
// lendo a cobrança ainda ATIVA, e o pagamento nunca liquidado pelo caminho do webhook.
func TestWebhookAvisoAntesDaLiquidacaoNaoQueimaAChave(t *testing.T) {
	t.Parallel()
	h, deps, tenantID := settleDivergenceHarness(t)

	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k-corrida",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}

	wh := app.NewWebhookService(deps)
	// A MESMA chave nas duas entregas — é o que o C6 manda, já que o corpo não tem
	// status para diferenciar uma da outra.
	ev := app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: p.TxID() + "|pix|"}

	// Primeira entrega: chega antes de o banco concluir. A cobrança ainda não está paga.
	if err := wh.HandlePaymentEvent(context.Background(), ev); err != nil {
		t.Fatalf("o aviso precoce deve ser aceito (202), got %v", err)
	}
	reloaded, _ := charges.GetPayment(context.Background(), tenantID, p.ID())
	if reloaded.Status() != payment.StatusPending {
		t.Fatalf("não devia ter liquidado ainda, status = %v", reloaded.Status())
	}

	// Agora o banco conclui.
	h.bank.MarkSettled(tenantID, p.TxID())

	// Segunda entrega, IDÊNTICA à primeira. Antes da correção, era deduplicada e o
	// pagamento morria pendente para sempre.
	if err := wh.HandlePaymentEvent(context.Background(), ev); err != nil {
		t.Fatalf("segunda entrega: %v", err)
	}

	reloaded, err = charges.GetPayment(context.Background(), tenantID, p.ID())
	if err != nil {
		t.Fatalf("get payment: %v", err)
	}
	if reloaded.Status() != payment.StatusPaid {
		t.Fatalf("o pagamento se perdeu: a chave de anti-replay foi queimada pelo aviso "+
			"precoce e a liquidação foi descartada como repetida (status = %v)", reloaded.Status())
	}
}

// A dedução continua valendo para o que É terminal: uma segunda entrega depois da
// liquidação não pode liquidar de novo nem reemitir aviso de venda.
func TestWebhookEntregaRepetidaDepoisDeLiquidarContinuaSendoNoOp(t *testing.T) {
	t.Parallel()
	h, deps, tenantID := settleDivergenceHarness(t)

	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k-repetida",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}
	h.bank.MarkSettled(tenantID, p.TxID())

	wh := app.NewWebhookService(deps)
	ev := app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: p.TxID() + "|pix|"}

	for i := 0; i < 3; i++ {
		if err := wh.HandlePaymentEvent(context.Background(), ev); err != nil {
			t.Fatalf("entrega %d: %v", i+1, err)
		}
	}

	reloaded, _ := charges.GetPayment(context.Background(), tenantID, p.ID())
	if reloaded.Status() != payment.StatusPaid {
		t.Fatalf("status = %v, want paid", reloaded.Status())
	}
}
