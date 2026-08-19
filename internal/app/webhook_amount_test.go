package app_test

import (
	"context"
	"testing"

	auditmem "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
)

// These tests cover the SIN-64777 amount-gate on the LIVE generic webhook
// settlement path: a charge the PSP marks paid but whose received amount diverges
// from the expected amount must NOT settle. Divergence is a terminal, audited,
// COMMITTING outcome — MarkProcessed is kept (so C6 does not redeliver forever)
// and a durable audit record of expected-vs-received is written.

// settleDivergenceHarness wires a harness with a real transactional store and an
// in-memory audit log, returning the pieces the divergence tests assert on.
// Deps.Audit is wired to an in-memory sink only so the standalone port is non-nil; the
// divergence entry does NOT go there. It commits on the TRANSACTION store (h.store),
// which is what the assertions read — see SIN-69580 and
// TestDivergenceAuditGoesThroughTransactionNotStandalonePort.
func settleDivergenceHarness(t *testing.T) (*harness, app.Deps, string) {
	t.Helper()
	h := newHarnessFor()
	tenantID := seedHarnessTenant(t, h)
	deps := h.deps
	deps.UoW = h.store
	deps.Audit = auditmem.NewLog()
	return h, deps, tenantID
}

func TestWebhookRefusesSettlementOnPartialPayment(t *testing.T) {
	t.Parallel()
	h, deps, tenantID := settleDivergenceHarness(t)

	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}

	// The PSP marks the charge paid, but only 60 of the expected 100 was received.
	h.bank.MarkSettledWithReceived(tenantID, p.TxID(), 60)
	wh := app.NewWebhookService(deps)

	ev := app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: "evt-1"}

	// The handler accepts (no error → 202) but must NOT settle.
	if err := wh.HandlePaymentEvent(context.Background(), ev); err != nil {
		t.Fatalf("divergence must commit (no error), got %v", err)
	}
	reloaded, _ := charges.GetPayment(context.Background(), tenantID, p.ID())
	if reloaded.Status() != payment.StatusPending {
		t.Fatalf("partial payment must NOT settle, status = %v", reloaded.Status())
	}

	// A durable audit record of the divergence was written, with the exact cents.
	// It lands on the TRANSACTION store, not the standalone Deps.Audit sink: the
	// append shares the settlement's unit of work (SIN-69580). In production both are
	// the same sqlite Store, so the row is the same either way — but appending on the
	// pool while the tx holds the write lock self-deadlocks with SQLITE_BUSY.
	entries := h.store.AuditEntries()
	if len(entries) != 1 {
		t.Fatalf("want exactly 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Action() != audit.ActionSettlementAmountMismatch {
		t.Fatalf("audit action = %q", e.Action())
	}
	if e.ExpectedCents() != 100 || e.ReceivedCents() != 60 {
		t.Fatalf("audit cents: expected=%d received=%d, want 100/60", e.ExpectedCents(), e.ReceivedCents())
	}
	if e.TxID() != p.TxID() || e.TenantID() != tenantID {
		t.Fatalf("audit identity: tx=%q tenant=%q", e.TxID(), e.TenantID())
	}

	// MarkProcessed was kept: the bank's redelivery (same event key) is a no-op,
	// so there is no infinite settle-retry loop and no second audit entry.
	if err := wh.HandlePaymentEvent(context.Background(), ev); err != nil {
		t.Fatalf("redelivery should be a no-op, got %v", err)
	}
	reloaded, _ = charges.GetPayment(context.Background(), tenantID, p.ID())
	if reloaded.Status() != payment.StatusPending {
		t.Fatal("redelivery must not settle a divergent charge")
	}
	if got := len(h.store.AuditEntries()); got != 1 {
		t.Fatalf("redelivery must not re-audit (MarkProcessed kept): audit len = %d, want 1", got)
	}
}

func TestWebhookRefusesSettlementOnOverpayment(t *testing.T) {
	t.Parallel()
	h, deps, tenantID := settleDivergenceHarness(t)

	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}

	// Overpayment is a divergence too (strict equality, not >=).
	h.bank.MarkSettledWithReceived(tenantID, p.TxID(), 150)
	wh := app.NewWebhookService(deps)

	if err := wh.HandlePaymentEvent(context.Background(), app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: "evt-1"}); err != nil {
		t.Fatalf("overpay divergence must commit, got %v", err)
	}
	reloaded, _ := charges.GetPayment(context.Background(), tenantID, p.ID())
	if reloaded.Status() != payment.StatusPending {
		t.Fatalf("overpayment must NOT settle, status = %v", reloaded.Status())
	}
	entries := h.store.AuditEntries()
	if len(entries) != 1 || entries[0].ExpectedCents() != 100 || entries[0].ReceivedCents() != 150 {
		t.Fatalf("want one audit entry 100/150, got %+v", entries)
	}
}

// TestWebhookFullPaymentStillSettlesAndDoesNotAudit is the positive control: a
// correctly-paid charge reconciles, settles, and writes NO divergence audit
// entry — the gate does not block legitimate settlements.
func TestWebhookFullPaymentStillSettlesAndDoesNotAudit(t *testing.T) {
	t.Parallel()
	h, deps, tenantID := settleDivergenceHarness(t)

	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}

	h.bank.MarkSettled(tenantID, p.TxID()) // full payment reconciles
	wh := app.NewWebhookService(deps)

	if err := wh.HandlePaymentEvent(context.Background(), app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: "evt-1"}); err != nil {
		t.Fatalf("full payment should settle, got %v", err)
	}
	reloaded, _ := charges.GetPayment(context.Background(), tenantID, p.ID())
	if reloaded.Status() != payment.StatusPaid {
		t.Fatalf("full payment must settle, status = %v", reloaded.Status())
	}
	if got := len(h.store.AuditEntries()); got != 0 {
		t.Fatalf("a reconciled settlement must not write a divergence audit entry, got %d", got)
	}
}

// TestWebhookNilAuditDivergenceDegradesToNoop confirms a nil Deps.Audit does not
// panic on divergence (foundation default), and the charge still is not settled.
func TestWebhookNilAuditDivergenceDegradesToNoop(t *testing.T) {
	t.Parallel()
	h := newHarnessFor()
	tenantID := seedHarnessTenant(t, h)
	deps := h.deps
	deps.UoW = h.store
	deps.Audit = nil // explicit: degrade to noop

	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}
	h.bank.MarkSettledWithReceived(tenantID, p.TxID(), 60)
	wh := app.NewWebhookService(deps)

	if err := wh.HandlePaymentEvent(context.Background(), app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: "evt-1"}); err != nil {
		t.Fatalf("nil audit must not error on divergence, got %v", err)
	}
	reloaded, _ := charges.GetPayment(context.Background(), tenantID, p.ID())
	if reloaded.Status() != payment.StatusPending {
		t.Fatal("divergent charge must not settle even with noop audit")
	}
}
