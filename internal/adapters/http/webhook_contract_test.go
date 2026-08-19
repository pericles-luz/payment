package http_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// The published C6 "Notificações" contract (v1.0.9) documents FOUR different inbound
// payloads on the same callback URL, not one envelope. The receiver previously decoded a
// single 4-field struct with DisallowUnknownFields and required external_id, so:
//
//   - the proprietary envelope was REJECTED (400) — it carries date_time and partner_id,
//     which the struct did not declare;
//   - the PIX envelope was REJECTED — it carries no external_id at all, and the settled
//     ids live inside `information`, a string holding JSON;
//   - the two recurrence payloads were REJECTED — BACEN shapes keyed by idRec/txid, with
//     no `service` field.
//
// Nothing surfaced this because no notification had ever arrived (processed_events was
// empty). These tests pin each documented shape so a settled payment cannot be dropped at
// the door again.

func TestWebhookAcceptsDocumentedProprietaryEnvelope(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, txID := seedCharge(t, f)

	// Exactly the documented fields — including date_time and partner_id, whose mere
	// presence used to produce a 400.
	body := map[string]any{
		"external_id": txID,
		"date_time":   "2025-11-26T18:02:36.261549917Z",
		"client_id":   tenantClientID,
		"partner_id":  "01J6W5RJTVB5CV1Z8QAB1K08QG",
		"service":     "BANK_SLIP",
		"status":      "PAID",
	}
	if rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+webhookRef, "", nil, body); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// A field the contract gains tomorrow must not break settlement today.
func TestWebhookToleratesUnknownFields(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, txID := seedCharge(t, f)

	body := map[string]any{
		"external_id":    txID,
		"client_id":      tenantClientID,
		"service":        "BANK_SLIP_PIX",
		"status":         "PAID",
		"a_future_field": "added by the PSP later",
		"another_object": map[string]any{"nested": true},
	}
	if rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+webhookRef, "", nil, body); rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// The PIX envelope identifies the settled payment by endToEndId, which can reach us three
// ways. All three must resolve: a PIX we cannot identify is money that never reconciles.
func TestWebhookResolvesPixEndToEndID(t *testing.T) {
	t.Parallel()

	// Each shape carries the SAME settled payment; only the way the end-to-end id reaches
	// us differs. Reconciling to 202 proves the id was extracted, not merely that the
	// body parsed.
	cases := []struct {
		name string
		body func(e2e string) map[string]any
	}{
		{
			name: "nested in the information string (documented envelope)",
			body: func(e2e string) map[string]any {
				return map[string]any{
					"date_time":   "2025-12-01T16:43:54.192482677Z",
					"status":      "PAID",
					"service":     "PIX",
					"key":         "23e454c1-c65b-4b28-9348-e4dd026aa27b",
					"tax_id":      "99367503000167",
					"information": `{"pix":[{"endToEndId":"` + e2e + `","valor":"100.00"}]}`,
				}
			},
		},
		{
			name: "top-level pix array (BACEN registration)",
			body: func(e2e string) map[string]any {
				return map[string]any{
					"service": "PIX",
					"status":  "PAID",
					"pix":     []any{map[string]any{"endToEndId": e2e, "valor": "100.00"}},
				}
			},
		},
		{
			name: "external_id fallback",
			body: func(e2e string) map[string]any {
				return map[string]any{"service": "pix", "status": "PAID", "external_id": e2e, "client_id": tenantClientID}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			_, txID := seedCharge(t, f)
			rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+webhookRef, "", nil, tc.body(txID))
			if rec.Code != http.StatusAccepted {
				t.Fatalf("want 202, got %d (%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// A PIX notification carrying nothing that identifies the payment is refused: settling
// against an empty id would reconcile the wrong thing, or nothing, silently.
func TestWebhookRejectsUnidentifiablePix(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	body := map[string]any{"service": "PIX", "status": "PAID", "information": `{"pix":[]}`}
	if rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+webhookRef, "", nil, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// The recurrence streams are keyed by idRec/txid and carry NO service discriminator —
// routing must come from the ids themselves.
func TestWebhookRoutesRecurrenceByIDs(t *testing.T) {
	t.Parallel()
	f := newRecFixture(t)
	ctx := context.Background()

	rec, err := f.stub.CreateRec(ctx, f.tenantID, ports.CreateRecRequest{
		Vinculo:             ports.RecVinculo{Contrato: "CT"},
		Calendario:          ports.RecCalendario{DataInicial: "2026-08-01", Periodicidade: ports.RecMensal},
		PoliticaRetentativa: ports.Retry3R7D,
	})
	if err != nil {
		t.Fatalf("seed rec: %v", err)
	}
	cobr, err := f.stub.CreateCobR(ctx, f.tenantID, ports.CreateCobRRequest{IDRec: rec.IDRec, TxID: "tx-1", ValorCents: 100})
	if err != nil {
		t.Fatalf("seed cobr: %v", err)
	}

	cases := []struct {
		name string
		body map[string]any
	}{
		{"rec: idRec alone", map[string]any{"idRec": rec.IDRec, "status": "APROVADA", "atualizacao": "2026-08-01T00:00:00Z"}},
		{"cobr: idRec + txid", map[string]any{"idRec": rec.IDRec, "txid": cobr.TxID, "status": "CONCLUIDA", "atualizacao": "2026-08-01T00:00:00Z"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+webhookRef, "", nil, tc.body)
			if r.Code != http.StatusAccepted {
				t.Fatalf("want 202, got %d (%s)", r.Code, r.Body.String())
			}
		})
	}
}

// A body that identifies nothing at all is refused rather than reconciled against "".
func TestWebhookRejectsUnidentifiableBody(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	body := map[string]any{"client_id": tenantClientID, "status": "PAID", "date_time": "2025-11-26T18:02:36Z"}
	if rec := do(t, f.handler, http.MethodPost, "/webhooks/c6/"+webhookRef, "", nil, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}
