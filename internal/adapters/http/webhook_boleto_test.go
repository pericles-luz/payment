package http_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// countPaid subscribes to the settled topic and returns a counter of dispatches.
func countPaid(t *testing.T, f *fixture) *int {
	t.Helper()
	n := 0
	_ = f.bus.Subscribe(context.Background(), app.TopicPaymentPaid, func(_ context.Context, _ ports.Message) error {
		n++
		return nil
	})
	return &n
}

// boletoNotice builds the C6 proprietary envelope for a boleto settlement.
func boletoNotice(externalID, clientID, service, status string) map[string]any {
	return map[string]any{
		"external_id": externalID,
		"client_id":   clientID,
		"service":     service,
		"status":      status,
	}
}

// A BANK_SLIP notification must reach the boleto reconcile path and actually settle.
//
// Until now it fell into the default branch, which reconciles through the PIX
// immediate-charge read — and a bank-slip id is not a PIX cob txid, so the read 404'd and a
// paid boleto stayed pending forever.
func TestWebhookBankSlipSettlesBoleto(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	boletoID, txID := seedBoleto(t, f, "wh-bs-1")
	f.bank.MarkBoletoStatus(f.tenantID, boletoID, "PAID")

	rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+f.webhookRef, "", nil,
		boletoNotice(txID, f.clientID, "BANK_SLIP", "PAID"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// The same for the BolePix discriminator.
func TestWebhookBankSlipPixSettlesBoleto(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	boletoID, txID := seedBoleto(t, f, "wh-bs-2")
	f.bank.MarkBoletoStatus(f.tenantID, boletoID, "PAID")

	rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+f.webhookRef, "", nil,
		boletoNotice(txID, f.clientID, "BANK_SLIP_PIX", "PAID"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// A BolePix is payable by boleto OR by PIX QR, so the same charge can notify under either
// discriminator. Both must collapse onto ONE settlement: the charge can only be paid once,
// and distinct event keys would publish two payment.paid events and two outbound webhooks
// to the Conta for a single payment.
func TestWebhookBoletoRailsShareOneEventKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	boletoID, txID := seedBoleto(t, f, "wh-bs-3")
	paid := countPaid(t, f)
	f.bank.MarkBoletoStatus(f.tenantID, boletoID, "PAID")
	url := "/webhooks/c6/" + f.webhookRef

	if rec := do(t, f.handler, http.MethodPost, url, "", nil,
		boletoNotice(txID, f.clientID, "BANK_SLIP", "PAID")); rec.Code != http.StatusAccepted {
		t.Fatalf("first notice: %d (%s)", rec.Code, rec.Body.String())
	}
	// The other rail, same charge, same status: an idempotent no-op, not a second settlement.
	if rec := do(t, f.handler, http.MethodPost, url, "", nil,
		boletoNotice(txID, f.clientID, "BANK_SLIP_PIX", "PAID")); rec.Code != http.StatusAccepted {
		t.Fatalf("second notice: %d (%s)", rec.Code, rec.Body.String())
	}

	if *paid != 1 {
		t.Fatalf("one payment must settle exactly once, got %d payment.paid events", *paid)
	}
}

// WAITING_CONFIRMATION means the payment is confirmed but the money is NOT in the
// merchant's account yet. It must not settle — our settlement contract with the Conta is
// "the money arrived" — and it must not be acked either, because acking depends on the bank
// sending a second notification when the funds land, which has not been verified. An
// unverified ack that turns out to be wrong loses the payment permanently.
func TestWebhookBoletoWaitingConfirmationDoesNotSettle(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	boletoID, txID := seedBoleto(t, f, "wh-bs-4")
	paid := countPaid(t, f)
	f.bank.MarkBoletoStatus(f.tenantID, boletoID, "WAITING_CONFIRMATION")

	rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+f.webhookRef, "", nil,
		boletoNotice(txID, f.clientID, "BANK_SLIP", "PAID"))
	if rec.Code == http.StatusAccepted {
		t.Fatal("WAITING_CONFIRMATION must NOT be acked: the PSP has to redeliver once the funds are credited")
	}
	if *paid != 0 {
		t.Fatal("no payment may be published while the funds are not credited")
	}
}

// Once the funds are credited, the redelivery settles — and the earlier refusal must not
// have burned the anti-replay key, or the redelivery would be acked as a duplicate no-op
// and the payment lost.
func TestWebhookBoletoSettlesOnRedeliveryAfterWaiting(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	boletoID, txID := seedBoleto(t, f, "wh-bs-5")
	paid := countPaid(t, f)
	url := "/webhooks/c6/" + f.webhookRef
	notice := boletoNotice(txID, f.clientID, "BANK_SLIP", "PAID")

	f.bank.MarkBoletoStatus(f.tenantID, boletoID, "WAITING_CONFIRMATION")
	if rec := do(t, f.handler, http.MethodPost, url, "", nil, notice); rec.Code == http.StatusAccepted {
		t.Fatal("the lagging notice must not be acked")
	}

	// The funds land; the PSP redelivers the SAME notification.
	f.bank.MarkBoletoStatus(f.tenantID, boletoID, "PAID")
	if rec := do(t, f.handler, http.MethodPost, url, "", nil, notice); rec.Code != http.StatusAccepted {
		t.Fatalf("redelivery must settle, got %d (%s)", rec.Code, rec.Body.String())
	}
	if *paid != 1 {
		t.Fatalf("expected exactly one settlement, got %d", *paid)
	}
}

// A cancelled charge is terminal and unpaid: acked, never settled.
func TestWebhookBoletoCanceledIsAckedNotSettled(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	boletoID, txID := seedBoleto(t, f, "wh-bs-6")
	paid := countPaid(t, f)
	f.bank.MarkBoletoStatus(f.tenantID, boletoID, "CANCELED")

	rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+f.webhookRef, "", nil,
		boletoNotice(txID, f.clientID, "BANK_SLIP", "CANCELED"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a cancelled charge must be acked, got %d (%s)", rec.Code, rec.Body.String())
	}
	if *paid != 0 {
		t.Fatal("a cancelled charge must never settle")
	}
}

// The notice claims PAID but the authoritative read says the charge is still open. The
// claim is never the truth, and a settlement we cannot confirm must not be confirmed to the
// PSP — it has to come back.
func TestWebhookBoletoClaimedPaidButStillOpenIsNotAcked(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, txID := seedBoleto(t, f, "wh-bs-7") // left at its registered status

	rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+f.webhookRef, "", nil,
		boletoNotice(txID, f.clientID, "BANK_SLIP", "PAID"))
	if rec.Code == http.StatusAccepted {
		t.Fatal("an unconfirmed settlement claim must not be acked")
	}
}
