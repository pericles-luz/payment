package http_test

import (
	"net/http"
	"strings"
	"testing"
)

// The body below is the REAL C6 PIX settlement notification, captured in production on
// 2026-08-19 (SIN-69580) after the receiver was instrumented to log what it rejected.
// Only the account-identifying values (end-to-end id and chave) are replaced; the shape,
// field names and types are verbatim:
//
//	{"pix":[{"endToEndId":"…","valor":"1.00","chave":"…","horario":"…","txid":"…"}]}
//
// Two things about it broke settlement, and both are pinned here:
//
//  1. There is NO `service` field. Routing gated the PIX branch on service=="PIX", so a
//     real notification matched no case and was refused with 400. C6 retried five times
//     and gave up; the charge stayed pending while the money was in the account.
//
//  2. The reconcile key is `txid`, not `endToEndId`. A payment row is keyed by the txid
//     the charge was created under; the end-to-end id is the BACEN transfer identifier
//     and matches no row, so reconciling by it would find nothing even once routing
//     worked.
//
// Nothing surfaced either failure because a rejected webhook produced no log line at all.

// liveC6PixBody is the captured notification, parameterised only by the txid so a test
// can point it at a seeded charge.
func liveC6PixBody(txID string) []byte {
	const tmpl = `{"pix":[{"endToEndId":"E00416968202608191600LlFCsq2cfiy",` +
		`"valor":"1.00","chave":"c7e43ff5-0000-0000-0000-000000000000",` +
		`"horario":"2026-08-19T16:00:18.849Z","txid":"%TXID%"}]}`
	return []byte(strings.Replace(tmpl, "%TXID%", txID, 1))
}

// The exact production payload must settle the charge it names.
func TestWebhookAcceptsLiveC6PixNotification(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, txID := seedCharge(t, f)

	rec := postRaw(t, f.handler, "/webhooks/c6/"+webhookRef, liveC6PixBody(txID))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("the real C6 settlement notification was refused: want 202, got %d (%s)",
			rec.Code, rec.Body.String())
	}
}

// Routing must not depend on a `service` field the PSP does not send: a bare pix array
// is a PIX settlement.
func TestWebhookRoutesPixWithoutServiceField(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, txID := seedCharge(t, f)

	body := []byte(`{"pix":[{"endToEndId":"E0041696820260819AAAA","txid":"` + txID + `"}]}`)
	if rec := postRaw(t, f.handler, "/webhooks/c6/"+webhookRef, body); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// txid wins over endToEndId: the charge is keyed by txid, so a notification carrying both
// must reconcile the charge rather than an id no row holds.
func TestWebhookPrefersTxIDOverEndToEndID(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, txID := seedCharge(t, f)

	// The e2e here belongs to no payment. If it were used as the reconcile key the
	// lookup would miss and this would not settle.
	body := []byte(`{"pix":[{"endToEndId":"E0041696820260819NOTAPAYMENT","txid":"` + txID + `"}]}`)
	if rec := postRaw(t, f.handler, "/webhooks/c6/"+webhookRef, body); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (%s) — reconcile likely used endToEndId, not txid",
			rec.Code, rec.Body.String())
	}
}

// A recurrence notification is routed by its own ids, not swallowed by the pix branch.
func TestWebhookRecurrenceNotCapturedByPixBranch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// idRec present and no pix array: must NOT resolve as a PIX settlement.
	body := []byte(`{"idRec":"RR00000000000000000000000000","status":"APROVADA"}`)
	rec := postRaw(t, f.handler, "/webhooks/c6/"+webhookRef, body)
	// The rec stream is not seeded in this fixture, so the routing decision shows up as
	// "not a 400 from unresolved shape" — anything but an unroutable-body rejection.
	if rec.Code == http.StatusBadRequest && strings.Contains(rec.Body.String(), "invalid request body") {
		t.Fatalf("recurrence notification was treated as unroutable: %d (%s)", rec.Code, rec.Body.String())
	}
}
