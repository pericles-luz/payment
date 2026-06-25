package bank

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// checkoutReq is the canonical two-item checkout request used by the stub checkout
// tests (1000 + 500 = 1500 cents).
func checkoutReq(sessionID string) ports.CheckoutRequest {
	return ports.CheckoutRequest{
		TenantID:  "t1",
		SessionID: sessionID,
		Currency:  "BRL",
		Items:     []ports.CheckoutItem{{Description: "a", AmountCents: 1000}, {Description: "b", AmountCents: 500}},
		CardType:  "credit",
	}
}

// TestStubCheckoutCreateGetCancel exercises the stub checkout lifecycle: open (roteiro
// 9) → reconcile (10) → cancel (11), asserting the session is retained, the total is
// summed, and cancel clears the redirect and flips the status.
func TestStubCheckoutCreateGetCancel(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()

	res, err := s.CreateCheckoutSession(ctx, "t1", checkoutReq("sess_1"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.SessionID != "sess_1" || res.Status != "OPEN" || res.AmountCents != 1500 || res.RedirectURL == "" {
		t.Fatalf("unexpected create result: %+v", res)
	}

	got, err := s.GetCheckoutSession(ctx, "t1", "sess_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "OPEN" || got.AmountCents != 1500 {
		t.Fatalf("unexpected get result: %+v", got)
	}

	cancelled, err := s.CancelCheckoutSession(ctx, "t1", "sess_1")
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if cancelled.Status != "CANCELLED" || cancelled.RedirectURL != "" {
		t.Fatalf("cancel should flip status and clear redirect: %+v", cancelled)
	}
	// Idempotent: cancelling again still succeeds and stays cancelled.
	again, err := s.CancelCheckoutSession(ctx, "t1", "sess_1")
	if err != nil || again.Status != "CANCELLED" {
		t.Fatalf("second cancel not idempotent: %+v err=%v", again, err)
	}
}

// TestStubCheckoutCreateIdempotent asserts opening the same (tenant, session id) twice
// returns the original session rather than re-opening it.
func TestStubCheckoutCreateIdempotent(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	first, err := s.CreateCheckoutSession(ctx, "t1", checkoutReq("sess_1"))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := s.CreateCheckoutSession(ctx, "t1", checkoutReq("sess_1"))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first != second {
		t.Fatalf("idempotent open should return the same session: %+v vs %+v", first, second)
	}
}

// TestStubCheckoutGetNotFound asserts an unknown session id within the tenant is
// ErrNotFound (no cross-tenant disclosure), and so is a session belonging to a
// different tenant.
func TestStubCheckoutGetNotFound(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	if _, err := s.GetCheckoutSession(ctx, "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}
	if _, err := s.CancelCheckoutSession(ctx, "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cancel unknown id: want ErrNotFound, got %v", err)
	}
}

// TestStubCheckoutMissingCredential asserts every checkout op resolves the tenant
// credential first, so an unknown tenant surfaces as ErrNotFound (per-tenant isolation).
func TestStubCheckoutMissingCredential(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	if _, err := s.CreateCheckoutSession(ctx, "unknown", checkoutReq("s")); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("create: want ErrNotFound, got %v", err)
	}
	if _, err := s.GetCheckoutSession(ctx, "unknown", "s"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("get: want ErrNotFound, got %v", err)
	}
	if _, err := s.CancelCheckoutSession(ctx, "unknown", "s"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cancel: want ErrNotFound, got %v", err)
	}
}

// TestStubCheckoutMarkPaid asserts the settlement test hooks reconcile the money: a
// full capture sets AmountReconciled, a divergent capture does not.
func TestStubCheckoutMarkPaid(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	if _, err := s.CreateCheckoutSession(ctx, "t1", checkoutReq("sess_1")); err != nil {
		t.Fatalf("create: %v", err)
	}

	s.MarkCheckoutPaid("t1", "sess_1")
	paid, _ := s.GetCheckoutSession(ctx, "t1", "sess_1")
	if paid.Status != "paid" || !paid.AmountReconciled() {
		t.Fatalf("full capture should reconcile: %+v", paid)
	}

	// A divergent capture (partial) must not reconcile.
	s.MarkCheckoutPaidWithReceived("t1", "sess_1", 1)
	diverged, _ := s.GetCheckoutSession(ctx, "t1", "sess_1")
	if diverged.AmountReconciled() {
		t.Fatalf("partial capture must not reconcile: %+v", diverged)
	}

	// Mark hooks are no-ops for an unknown session (no panic, no entry created).
	s.MarkCheckoutPaid("t1", "ghost")
	if _, err := s.GetCheckoutSession(ctx, "t1", "ghost"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("mark must not create a session: %v", err)
	}
}
