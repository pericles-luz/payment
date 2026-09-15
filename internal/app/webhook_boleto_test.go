package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// seedTenantForBoleto creates a tenant with a bank credential, which the boleto service and
// the stub bank both require.
func seedTenantForBoleto(t *testing.T, h *harness) string {
	t.Helper()
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	return tn.ID()
}

// registerBoletoForSettlement registers a boleto through the service and returns the local
// boleto id together with the bank tx id a notification would carry.
func registerBoletoForSettlement(t *testing.T, h *harness, tenantID, idemKey string) (boletoID, txID string) {
	t.Helper()
	svc := app.NewBoletoService(h.deps)
	in := app.RegisterBoletoInput{
		TenantID:    tenantID,
		AmountCents: 100000,
		Currency:    "BRL",
		DueDate:     time.Now().Add(240 * time.Hour).UTC(),
		Payer: app.BoletoPayerInput{
			Name: "Fulano", TaxID: "12345678901",
			Address: app.BoletoAddressInput{
				Street: "Rua A", Number: 1, Neighborhood: "Centro",
				City: "Brasília", State: "DF", ZipCode: "70000000",
			},
		},
		Description:    "Mensalidade",
		IdempotencyKey: idemKey,
		Modality:       ports.ModalityBolepix,
	}
	p, res, err := svc.RegisterBoleto(context.Background(), in)
	if err != nil {
		t.Fatalf("register boleto: %v", err)
	}
	return p.ID(), res.TxID
}

func boletoEvent(tenantID, txID, key string) app.PaymentEvent {
	return app.PaymentEvent{TenantID: tenantID, TxID: txID, EventKey: key, ClaimsSettlement: true}
}

// A registered boleto the bank reports as PAID settles the local payment.
func TestHandleBoletoEventSettlesPaidCharge(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	tenantID := seedTenantForBoleto(t, h)
	boletoID, txID := registerBoletoForSettlement(t, h, tenantID, "set-1")
	h.bank.MarkBoletoStatus(tenantID, boletoID, "PAID")

	svc := app.NewWebhookService(h.deps)
	if err := svc.HandleBoletoEvent(context.Background(), boletoEvent(tenantID, txID, "k1")); err != nil {
		t.Fatalf("HandleBoletoEvent: %v", err)
	}
	reloaded, err := h.store.FindPaymentByTxID(context.Background(), tenantID, txID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Status() != payment.StatusPaid {
		t.Fatalf("status = %v, want paid", reloaded.Status())
	}
}

// WAITING_CONFIRMATION is money confirmed but NOT credited. It must not settle, and it must
// come back as an error so the PSP redelivers — acking it would depend on a second
// notification nobody has verified the bank sends.
func TestHandleBoletoEventWaitingConfirmationAsksForRedelivery(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	tenantID := seedTenantForBoleto(t, h)
	boletoID, txID := registerBoletoForSettlement(t, h, tenantID, "set-2")
	h.bank.MarkBoletoStatus(tenantID, boletoID, "WAITING_CONFIRMATION")

	svc := app.NewWebhookService(h.deps)
	err := svc.HandleBoletoEvent(context.Background(), boletoEvent(tenantID, txID, "k2"))
	if err == nil {
		t.Fatal("WAITING_CONFIRMATION must surface as an error so the PSP redelivers")
	}
	reloaded, _ := h.store.FindPaymentByTxID(context.Background(), tenantID, txID)
	if reloaded.Status() == payment.StatusPaid {
		t.Fatal("a charge whose funds are not credited must not be settled")
	}
}

// And the refusal must not burn the anti-replay key: the redelivery has to be processed for
// real, not swallowed as a duplicate.
func TestHandleBoletoEventSettlesAfterWaitingRedelivery(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	tenantID := seedTenantForBoleto(t, h)
	boletoID, txID := registerBoletoForSettlement(t, h, tenantID, "set-3")
	svc := app.NewWebhookService(h.deps)
	ev := boletoEvent(tenantID, txID, "k3")

	h.bank.MarkBoletoStatus(tenantID, boletoID, "WAITING_CONFIRMATION")
	if err := svc.HandleBoletoEvent(context.Background(), ev); err == nil {
		t.Fatal("the lagging delivery must not be acked")
	}

	h.bank.MarkBoletoStatus(tenantID, boletoID, "PAID")
	if err := svc.HandleBoletoEvent(context.Background(), ev); err != nil {
		t.Fatalf("redelivery must settle: %v", err)
	}
	reloaded, _ := h.store.FindPaymentByTxID(context.Background(), tenantID, txID)
	if reloaded.Status() != payment.StatusPaid {
		t.Fatalf("status = %v, want paid after redelivery", reloaded.Status())
	}
}

// A cancelled charge is terminal and unpaid: acked, never settled.
func TestHandleBoletoEventCanceledIsAcked(t *testing.T) {
	t.Parallel()
	for _, spelling := range []string{"CANCELED", "CANCELLED"} {
		t.Run(spelling, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			tenantID := seedTenantForBoleto(t, h)
			boletoID, txID := registerBoletoForSettlement(t, h, tenantID, "set-c-"+spelling)
			h.bank.MarkBoletoStatus(tenantID, boletoID, spelling)

			svc := app.NewWebhookService(h.deps)
			ev := boletoEvent(tenantID, txID, "kc-"+spelling)
			ev.ClaimsSettlement = false
			if err := svc.HandleBoletoEvent(context.Background(), ev); err != nil {
				t.Fatalf("a cancelled charge must be acked, got %v", err)
			}
			reloaded, _ := h.store.FindPaymentByTxID(context.Background(), tenantID, txID)
			if reloaded.Status() == payment.StatusPaid {
				t.Fatal("a cancelled charge must never settle")
			}
		})
	}
}

// A nil boleto port fails CLOSED. Dropping a settlement notification silently is the one
// outcome that loses money without leaving a trace.
func TestHandleBoletoEventUnconfiguredFailsClosed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	deps := h.deps
	deps.Boleto = nil
	svc := app.NewWebhookService(deps)

	err := svc.HandleBoletoEvent(context.Background(), boletoEvent("t1", "tx", "k"))
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

// A blank tx id is refused rather than reconciled against an empty id.
func TestHandleBoletoEventRequiresTxID(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	svc := app.NewWebhookService(h.deps)

	err := svc.HandleBoletoEvent(context.Background(), app.PaymentEvent{TenantID: "t1", EventKey: "k"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

// An id that maps to no local payment AND to no charge at the bank must fail loudly, not be
// acked away: acking an id we could not map is indistinguishable from acking a real payment
// whose mapping we got wrong.
func TestHandleBoletoEventUnknownIDFailsLoudly(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	tenantID := seedTenantForBoleto(t, h)
	svc := app.NewWebhookService(h.deps)

	err := svc.HandleBoletoEvent(context.Background(), boletoEvent(tenantID, "01NOSUCHCHARGE0000000000AB", "k-unknown"))
	if err == nil {
		t.Fatal("an unmapped notification must not be acked")
	}
}
