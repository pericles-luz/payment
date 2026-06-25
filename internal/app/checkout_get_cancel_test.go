package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// openCheckout opens a session via the service and returns its session id (= payment
// id) for the get/cancel/webhook tests.
func openCheckout(t *testing.T, svc *app.CheckoutService, tenantID, idemKey string) string {
	t.Helper()
	p, res, err := svc.CreateSession(context.Background(), baseCheckoutInput(tenantID, idemKey))
	if err != nil {
		t.Fatalf("open checkout: %v", err)
	}
	if res.SessionID != p.ID() {
		t.Fatalf("session id should equal payment id: %s vs %s", res.SessionID, p.ID())
	}
	return res.SessionID
}

// TestCheckoutGetSession covers roteiro 10: reconcile a session, plus the boundary
// validation and the no-cross-tenant-oracle guarantees.
func TestCheckoutGetSession(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newCheckoutHarness(t)
	sessionID := openCheckout(t, svc, tenantID, "k-get")

	res, err := svc.GetSession(context.Background(), tenantID, sessionID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if res.SessionID != sessionID || res.Status != "OPEN" || res.AmountCents != 1250 {
		t.Fatalf("unexpected result: %+v", res)
	}

	// Empty id is a boundary validation error (never reaches the bank).
	if _, err := svc.GetSession(context.Background(), tenantID, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id: want ErrValidation, got %v", err)
	}
	// Unknown id within the tenant is not-found.
	if _, err := svc.GetSession(context.Background(), tenantID, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}
	// A session owned by another tenant is not-found (no cross-tenant disclosure).
	if _, err := svc.GetSession(context.Background(), "other-tenant", sessionID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant: want ErrNotFound, got %v", err)
	}
}

// TestCheckoutCancelSession covers roteiro 11: cancel is idempotent, validated at the
// boundary, and never confirms existence cross-tenant.
func TestCheckoutCancelSession(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newCheckoutHarness(t)
	sessionID := openCheckout(t, svc, tenantID, "k-cancel")

	res, err := svc.CancelSession(context.Background(), tenantID, sessionID)
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if res.Status != "CANCELLED" {
		t.Fatalf("want CANCELLED, got %+v", res)
	}
	// Idempotent: a repeat cancel still succeeds and stays cancelled.
	again, err := svc.CancelSession(context.Background(), tenantID, sessionID)
	if err != nil || again.Status != "CANCELLED" {
		t.Fatalf("repeat cancel not idempotent: %+v err=%v", again, err)
	}

	if _, err := svc.CancelSession(context.Background(), tenantID, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty id: want ErrValidation, got %v", err)
	}
	if _, err := svc.CancelSession(context.Background(), tenantID, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}
	if _, err := svc.CancelSession(context.Background(), "other-tenant", sessionID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant: want ErrNotFound, got %v", err)
	}
}

// TestCheckoutWebhookSettlement covers roteiro 12: a checkout notification only
// settles after reconciling the session's authoritative state with the bank, money
// included, and duplicate deliveries are deduped.
func TestCheckoutWebhookSettlement(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newCheckoutHarness(t)
	sessionID := openCheckout(t, svc, tenantID, "k-wh")
	wh := app.NewWebhookService(h.deps)
	charges := app.NewChargeService(h.deps)

	// Session still OPEN at the bank → notification accepted but no settlement.
	if err := wh.HandleCheckoutEvent(context.Background(), app.PaymentEvent{TenantID: tenantID, TxID: sessionID, EventKey: sessionID + "|checkout|open"}); err != nil {
		t.Fatalf("pending webhook: %v", err)
	}
	reloaded, err := charges.GetPayment(context.Background(), tenantID, sessionID)
	if err != nil {
		t.Fatalf("get payment: %v", err)
	}
	if reloaded.Status() != payment.StatusPending {
		t.Fatalf("should still be pending before capture, got %s", reloaded.Status())
	}

	// Bank captures the full amount → a paid notification reconciles and settles.
	h.bank.MarkCheckoutPaid(tenantID, sessionID)
	if err := wh.HandleCheckoutEvent(context.Background(), app.PaymentEvent{TenantID: tenantID, TxID: sessionID, EventKey: sessionID + "|checkout|paid"}); err != nil {
		t.Fatalf("settle webhook: %v", err)
	}
	reloaded, _ = charges.GetPayment(context.Background(), tenantID, sessionID)
	if reloaded.Status() != payment.StatusPaid {
		t.Fatalf("should be paid after reconciliation, got %s", reloaded.Status())
	}

	// Replay of the same event is a deduped no-op.
	if err := wh.HandleCheckoutEvent(context.Background(), app.PaymentEvent{TenantID: tenantID, TxID: sessionID, EventKey: sessionID + "|checkout|paid"}); err != nil {
		t.Fatalf("replay: %v", err)
	}
}

// TestCheckoutWebhookAmountDivergenceRefusesSettle asserts reconcile-before-settle
// (threat W3): a captured amount that diverges from the authorized total is accepted
// (202) and audited but never settled.
func TestCheckoutWebhookAmountDivergenceRefusesSettle(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newCheckoutHarness(t)
	sessionID := openCheckout(t, svc, tenantID, "k-div")
	wh := app.NewWebhookService(h.deps)
	charges := app.NewChargeService(h.deps)

	h.bank.MarkCheckoutPaidWithReceived(tenantID, sessionID, 1) // partial capture
	if err := wh.HandleCheckoutEvent(context.Background(), app.PaymentEvent{TenantID: tenantID, TxID: sessionID, EventKey: sessionID + "|checkout|paid"}); err != nil {
		t.Fatalf("divergent webhook should be accepted, got %v", err)
	}
	reloaded, _ := charges.GetPayment(context.Background(), tenantID, sessionID)
	if reloaded.Status() != payment.StatusPending {
		t.Fatalf("a divergent capture must NOT settle, got %s", reloaded.Status())
	}
}

// TestCheckoutWebhookNotConfigured asserts the checkout-webhook path fails closed when
// the checkout port is not wired, rather than panicking or silently dropping the event.
func TestCheckoutWebhookNotConfigured(t *testing.T) {
	t.Parallel()
	h := newHarness(t) // deps.Checkout is nil
	wh := app.NewWebhookService(h.deps)
	err := wh.HandleCheckoutEvent(context.Background(), app.PaymentEvent{TenantID: "t", TxID: "s", EventKey: "s|checkout|paid"})
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("unconfigured checkout webhook should be ErrUnavailable, got %v", err)
	}
}
