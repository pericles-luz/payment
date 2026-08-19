package c6

import (
	"context"
	"net/http"
	"testing"
)

// The body below is the REAL C6 response for a PAID checkout, captured in production on
// 2026-08-19 (SIN-69580). Only account-identifying values are masked; the shape, field
// names and types are verbatim.
//
// It settles a question that had only ever been answered from a code comment: there is
// NO captured_amount. The field documented "EM BREVE" has no representation in this
// contract — and neither does a partial capture, so there is no field a lesser captured
// value could even arrive in. Holding ReceivedAmountCents at zero waiting for it did not
// implement the W3 amount gate; it implemented "no checkout ever settles", indefinitely.
//
// What the response DOES carry is an affirmed capture: status PAID plus
// payment.card.return_code "00" alongside "Transacao capturada com sucesso". Settlement
// now requires BOTH, so a status flipped without a matching capture still does not
// liquidate money.
const liveC6PaidCheckoutBody = `{"id":"chk_live","external_reference_id":"20260819153419",` +
	`"emission_date_time":"2026-08-19T18:34:20.000Z","expiration_date_time":"2026-08-20T21:34:19.000Z",` +
	`"amount":5.01,"status":"PAID","payment_date_time":"2026-08-19T18:51:13.000Z",` +
	`"payment":{"card":{"card_info":{"number":"651653******9042","brand":"ELO","holder_name":"*****"},` +
	`"type":"CREDIT","installments":1,"interest_type":"BY_SELLER","authenticate":"NOT_REQUIRED",` +
	`"save_card":false,"recurrent":false,"authorization_code":"623194","return_code":"00",` +
	`"message":"Transacao capturada com sucesso"}},"payer":{"tax_id":"*******.036-72"},` +
	`"fraud_analysis":{"analyzed":true,"recommendation":"APPROVE"}}`

// serveCheckoutBody points the double's GET at a fixed body.
func serveCheckoutBody(cs *checkoutRWServer, body string) {
	cs.get = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

// The exact production payload must reconcile, so the shared settlement core liquidates.
func TestGetCheckoutSessionSettlesOnCapturedPayment(t *testing.T) {
	t.Parallel()
	cs := newCheckoutRWServer(t)
	serveCheckoutBody(cs, liveC6PaidCheckoutBody)
	p := cs.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.GetCheckoutSession(context.Background(), "t1", "chk_live")
	if err != nil {
		t.Fatalf("GetCheckoutSession: %v", err)
	}
	// 5.01 reais is exactly 501 cents — parsed by string, never through a float.
	if res.AmountCents != 501 {
		t.Fatalf("amount: want 501 cents from 5.01 reais, got %d", res.AmountCents)
	}
	if res.ReceivedAmountCents != 501 {
		t.Fatalf("an affirmed capture must reconcile for the authorized total, got %d", res.ReceivedAmountCents)
	}
	if !res.AmountReconciled() {
		t.Fatalf("the real paid checkout must reconcile so it can settle: %+v", res)
	}
	if res.Installments != 1 {
		t.Fatalf("installments: want 1, got %d", res.Installments)
	}
	if res.Message != "Transacao capturada com sucesso" {
		t.Fatalf("message not carried through: %q", res.Message)
	}
}

// A declined card must not settle, even though the session says PAID: the return code is
// the half of the gate that distinguishes an authorised capture from a status flip.
func TestGetCheckoutSessionRefusesUnapprovedReturnCode(t *testing.T) {
	t.Parallel()
	cs := newCheckoutRWServer(t)
	serveCheckoutBody(cs, `{"id":"chk_x","status":"PAID","amount":5.01,`+
		`"payment":{"card":{"installments":1,"return_code":"51","message":"Transacao negada"}}}`)
	p := cs.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.GetCheckoutSession(context.Background(), "t1", "chk_x")
	if err != nil {
		t.Fatalf("GetCheckoutSession: %v", err)
	}
	if res.ReceivedAmountCents != 0 || res.AmountReconciled() {
		t.Fatalf("a declined card must NOT reconcile: %+v", res)
	}
}

// An open (unpaid) session must not settle.
func TestGetCheckoutSessionRefusesUnpaidStatus(t *testing.T) {
	t.Parallel()
	cs := newCheckoutRWServer(t)
	serveCheckoutBody(cs, `{"id":"chk_o","status":"CREATED","amount":5.01,`+
		`"payment":{"card":{"return_code":"00"}}}`)
	p := cs.provider(t, oneTenant("t1", "client-1", "secret-1"))

	res, err := p.GetCheckoutSession(context.Background(), "t1", "chk_o")
	if err != nil {
		t.Fatalf("GetCheckoutSession: %v", err)
	}
	if res.ReceivedAmountCents != 0 || res.AmountReconciled() {
		t.Fatalf("an open session must NOT reconcile: %+v", res)
	}
}
