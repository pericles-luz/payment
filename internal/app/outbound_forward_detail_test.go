package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
)

// The envelope forwarded to a Conta's endpoint carried only routing fields, so a
// reseller learned THAT something settled but not for how much, in how many parcelas, or
// what the PSP said — it had to call our API back for every event. A card checkout in
// particular settles in installments the empresa needs in order to reconcile.
//
// These tests pin the three added fields and, above all, the UNIT: amounts cross this
// boundary as integer CENTS. The PSP reports checkout amounts as decimal reais on the
// wire ("amount": 5.01); the adapter parses those to cents by string, never a float. A
// reais-valued amount here would be a money bug — 5.01 must arrive as 501.

func TestForwardBodyCarriesSettlementDetailInCents(t *testing.T) {
	t.Parallel()
	d := outboundqueue.RehydrateDelivery(
		"del-1", "acct-1", "ten-1", "ek-1", "tx-1", "payment.paid",
		outboundqueue.StatusPending, time.Unix(1700000000, 0).UTC(),
		outboundqueue.Detail{AmountCents: 501, Installments: 3, Message: "Transacao capturada com sucesso"},
	)

	raw, err := buildForwardBody(d, time.Unix(1700000123, 0).UTC())
	if err != nil {
		t.Fatalf("buildForwardBody: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if v, ok := got["amount_cents"].(float64); !ok || int64(v) != 501 {
		t.Fatalf("amount_cents must be integer cents (501 for R$ 5,01), got %v", got["amount_cents"])
	}
	if v, ok := got["installments"].(float64); !ok || int(v) != 3 {
		t.Fatalf("installments: want 3, got %v", got["installments"])
	}
	if got["message"] != "Transacao capturada com sucesso" {
		t.Fatalf("message: got %v", got["message"])
	}
	// No decimal/reais field may leak alongside it.
	if _, present := got["amount"]; present {
		t.Fatal("a reais-valued `amount` must never be forwarded; cents is the only unit that crosses")
	}
	// The routing fields still travel unchanged.
	for k, want := range map[string]string{
		"event_key": "ek-1", "event_type": "payment.paid", "tx_id": "tx-1", "account_id": "acct-1",
	} {
		if got[k] != want {
			t.Fatalf("%s: want %q, got %v", k, want, got[k])
		}
	}
}

// A PIX or boleto settlement has no card detail; the fields must be present and zero
// rather than absent, so a receiver can parse one stable schema.
func TestForwardBodyZeroDetailForNonCard(t *testing.T) {
	t.Parallel()
	d := outboundqueue.RehydrateDelivery(
		"del-2", "acct-1", "ten-1", "ek-2", "tx-2", "payment.paid",
		outboundqueue.StatusPending, time.Unix(1700000000, 0).UTC(),
		outboundqueue.Detail{AmountCents: 100},
	)

	raw, err := buildForwardBody(d, time.Unix(1700000123, 0).UTC())
	if err != nil {
		t.Fatalf("buildForwardBody: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := got["installments"]; !present {
		t.Fatal("installments must be present (zero) so the schema is stable")
	}
	if v, _ := got["installments"].(float64); int(v) != 0 {
		t.Fatalf("installments: want 0 for a non-card settlement, got %v", got["installments"])
	}
	if got["message"] != "" {
		t.Fatalf("message: want empty for a non-card settlement, got %v", got["message"])
	}
}
