package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
)

// The divergence audit MUST be appended through the transaction's repository, never
// through the standalone Deps.Audit port.
//
// Against SQLite those are two different connections to one file. The standalone port
// writes on the *sql.DB pool, so appending through it while WithinTx already holds the
// write lock is a self-deadlock inside a single process: SQLite answers SQLITE_BUSY at
// once, the error propagates, WithinTx rolls the whole unit of work back — MarkProcessed
// included — and the handler returns 500. The PSP redelivers into the identical deadlock
// until it gives up, so the divergence is never recorded and the notification never
// acked. That is exactly what production did to every checkout notification (SIN-69580):
//
//	record settlement divergence: append audit entry: append audit entry:
//	database is locked (5) (SQLITE_BUSY)
//
// The existing divergence tests could not catch it because they wire an in-MEMORY audit
// log, which holds no database handle and therefore cannot contend with anything.
//
// This test removes that blind spot without needing SQLite: Deps.Audit is a port that
// ALWAYS fails. If the service still appended through it, the divergence would error out
// and the settlement path would break. Passing proves the append travelled on the
// transaction handle instead.

// alwaysFailingAudit stands in for a standalone audit port that cannot be used from
// inside an open transaction — the role SQLite's pool connection plays in production.
type alwaysFailingAudit struct{ calls int }

var errStandaloneAuditUsed = errors.New("standalone audit port used inside a transaction (would deadlock on sqlite)")

func (a *alwaysFailingAudit) Append(context.Context, audit.Entry) error {
	a.calls++
	return errStandaloneAuditUsed
}

func TestDivergenceAuditGoesThroughTransactionNotStandalonePort(t *testing.T) {
	t.Parallel()
	h := newHarnessFor()
	tenantID := seedHarnessTenant(t, h)

	sink := &alwaysFailingAudit{}
	deps := h.deps
	deps.UoW = h.store
	deps.Audit = sink // unusable from inside the tx, exactly like the sqlite pool

	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 501, Currency: "BRL", IdempotencyKey: "k-div-tx",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}

	// Paid at the PSP, but the received amount diverges — the branch that records the
	// audit entry. A checkout reaches this branch on EVERY notification today, because
	// C6 does not yet return captured_amount.
	h.bank.MarkSettledWithReceived(tenantID, p.TxID(), 0)

	wh := app.NewWebhookService(deps)
	ev := app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: "evt-div-tx"}

	if err := wh.HandlePaymentEvent(context.Background(), ev); err != nil {
		t.Fatalf("divergence must commit through the tx (202), got %v — the audit append "+
			"went to the standalone port, which deadlocks on sqlite", err)
	}
	if sink.calls != 0 {
		t.Fatalf("standalone audit port was called %d time(s); the divergence append must "+
			"run on the transaction handle", sink.calls)
	}

	// And the outcome itself is unchanged: refused settlement, still pending.
	reloaded, err := charges.GetPayment(context.Background(), tenantID, p.ID())
	if err != nil {
		t.Fatalf("get payment: %v", err)
	}
	if reloaded.Status() != payment.StatusPending {
		t.Fatalf("divergence must NOT settle, status = %v", reloaded.Status())
	}
}

// The divergence must still be durably recorded — moving the append onto the
// transaction must not silently drop the trail.
func TestDivergenceAuditIsStillRecorded(t *testing.T) {
	t.Parallel()
	h := newHarnessFor()
	tenantID := seedHarnessTenant(t, h)

	deps := h.deps
	deps.UoW = h.store
	deps.Audit = &alwaysFailingAudit{}

	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k-div-rec",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}
	h.bank.MarkSettledWithReceived(tenantID, p.TxID(), 60)

	wh := app.NewWebhookService(deps)
	ev := app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: "evt-div-rec"}
	if err := wh.HandlePaymentEvent(context.Background(), ev); err != nil {
		t.Fatalf("divergence must commit, got %v", err)
	}

	var found bool
	for _, e := range h.store.AuditEntries() {
		if e.TxID() == p.TxID() && e.ExpectedCents() == 100 && e.ReceivedCents() == 60 {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("divergence audit entry was not recorded on the transaction store")
	}
}
