package app_test

import (
	"context"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
)

// End-to-end proof of the F1 seam (SIN-69491): a full, reconciled settlement on the
// inbound webhook path materialises the event onto its owning Conta's outbound-delivery
// outbox — when (and only when) the attributor is enabled — keyed by the resolved
// accountID and the inbound event_key. This is the integration counterpart to the
// attributor unit tests, exercising the publishSettled → Attribute wiring through a
// real transactional settle.

func TestWebhookSettlementMaterialisesOutboundDelivery(t *testing.T) {
	t.Parallel()
	h, deps, tenantID := settleDivergenceHarness(t)

	store := inmemory.NewOutboundDeliveryStore()
	deps.OutboundAttributor = app.NewOutboundAttributor(app.OutboundAttributorDeps{
		Enabled:     true,
		Resolver:    &fakeAccountResolver{accountID: "acct-verz"},
		Queue:       store,
		DeadLetters: store,
		Clock:       fixedClock{t: obNow},
		IDs:         &seqIDs{},
	})

	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}
	h.bank.MarkSettled(tenantID, p.TxID()) // full payment reconciles → settles

	wh := app.NewWebhookService(deps)
	if err := wh.HandlePaymentEvent(context.Background(), app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: "evt-1"}); err != nil {
		t.Fatalf("settle: %v", err)
	}

	got, err := store.PendingDeliveries(context.Background(), "acct-verz")
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 outbox delivery after settlement, got %d", len(got))
	}
	d := got[0]
	if d.AccountID() != "acct-verz" || d.TenantID() != tenantID || d.EventKey() != "evt-1" ||
		d.TxID() != p.TxID() || d.EventType() != app.TopicPaymentPaid {
		t.Fatalf("delivery fields wrong: %+v", d)
	}
}

// Dark by default: with NO attributor wired (or the flag off), a settlement runs
// exactly as before and nothing is materialised — proving zero effect on the current
// settle flow until the feature is turned on.
func TestWebhookSettlementDarkWithoutAttributor(t *testing.T) {
	t.Parallel()
	h, deps, tenantID := settleDivergenceHarness(t)
	// deps.OutboundAttributor left nil (dark default).

	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}
	h.bank.MarkSettled(tenantID, p.TxID())

	wh := app.NewWebhookService(deps)
	if err := wh.HandlePaymentEvent(context.Background(), app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: "evt-1"}); err != nil {
		t.Fatalf("settle must succeed with dark attributor: %v", err)
	}
	// No panic, no error — the settlement is unaffected. (Nothing to assert on an
	// absent store; the point is the nil attributor is a safe no-op in the live path.)
}
