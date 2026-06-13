package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// These tests cover the SIN-64719 atomicity fixes end-to-end against the real
// in-memory transactional store (a production-faithful UnitOfWork), with thin
// decorators injecting transient infrastructure failures. They are the
// regression suite required by the issue's acceptance criteria:
//
//	(a) a ledger failure never leaves a charged-but-unbilled payment (F1);
//	(b) a transient reconcile error in the webhook does not suppress settlement
//	    on the bank's redelivery (F2);
//	(c) retry/concurrency with the same idempotency key never double-charges (F3a).

// wrapUoW decorates a real UnitOfWork, wrapping the Repository handed to each
// transaction so a test can inject per-operation failures while still exercising
// genuine commit/rollback semantics.
type wrapUoW struct {
	inner ports.UnitOfWork
	wrap  func(ports.Repository) ports.Repository
}

func (u wrapUoW) WithinTx(ctx context.Context, fn func(ports.Repository) error) error {
	return u.inner.WithinTx(ctx, func(r ports.Repository) error {
		return fn(u.wrap(r))
	})
}

var errLedgerDown = errors.New("ledger unavailable")

// ledgerFailRepo fails the next *remaining AppendLedgerEntry calls, then behaves
// normally. Everything else delegates to the wrapped transactional repository.
type ledgerFailRepo struct {
	ports.Repository
	remaining *int
}

func (r ledgerFailRepo) AppendLedgerEntry(ctx context.Context, e billing.LedgerEntry) error {
	if *r.remaining > 0 {
		*r.remaining--
		return errLedgerDown
	}
	return r.Repository.AppendLedgerEntry(ctx, e)
}

var errBankDown = errors.New("bank unavailable")

// flakyBank fails the next *failGets GetCharge calls, then delegates. CreateCharge
// is left untouched (delegated) so a charge can be created normally.
type flakyBank struct {
	ports.BankProvider
	failGets *int
}

func (b flakyBank) GetCharge(ctx context.Context, tenantID, txID string) (ports.ChargeResult, error) {
	if *b.failGets > 0 {
		*b.failGets--
		return ports.ChargeResult{}, errBankDown
	}
	return b.BankProvider.GetCharge(ctx, tenantID, txID)
}

// seedHarnessTenant creates an active tenant, sets its bank credential and prices an
// endpoint, returning the tenant id. It uses the harness deps (in-memory store).
func seedHarnessTenant(t *testing.T, h *harness) string {
	t.Helper()
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), "pix.create", 99); err != nil {
		t.Fatalf("set price: %v", err)
	}
	return tn.ID()
}

// (a) F1 — a ledger append failure must roll back the whole finalize (no
// half-written payment), and a retry must bill the payment exactly once rather
// than returning it permanently unbilled.
func TestCreateChargeLedgerFailureLeavesNoUnbilledPayment(t *testing.T) {
	t.Parallel()
	h := newHarnessFor()
	tenantID := seedHarnessTenant(t, h)

	remaining := 1 // fail the first ledger append, then recover
	deps := h.deps
	deps.UoW = wrapUoW{inner: h.store, wrap: func(r ports.Repository) ports.Repository {
		return ledgerFailRepo{Repository: r, remaining: &remaining}
	}}
	charges := app.NewChargeService(deps)
	in := app.CreateChargeInput{TenantID: tenantID, Endpoint: "pix.create", AmountCents: 5000, Currency: "BRL", IdempotencyKey: "k1"}

	// First attempt: the ledger append fails inside the finalize transaction.
	if _, err := charges.CreateCharge(context.Background(), in); !errors.Is(err, errLedgerDown) {
		t.Fatalf("want ledger failure, got %v", err)
	}
	if got := h.store.LedgerLen(); got != 0 {
		t.Fatalf("finalize must roll back atomically: ledger len = %d, want 0", got)
	}

	// Retry with the same key: the reservation is resumed and billed exactly once.
	p, err := charges.CreateCharge(context.Background(), in)
	if err != nil {
		t.Fatalf("retry after ledger recovery: %v", err)
	}
	if p.TxID() == "" {
		t.Fatal("resumed charge must carry a bank tx id")
	}
	if got := h.store.LedgerLen(); got != 1 {
		t.Fatalf("payment must be billed exactly once after resume: ledger len = %d, want 1", got)
	}
	if got := h.bank.ChargeCount(); got != 1 {
		t.Fatalf("must charge the bank exactly once: charge count = %d, want 1", got)
	}
}

// (b) F2 — a transient reconcile error rolls back the processed-event mark, so the
// bank's redelivery (same event key) is reprocessed and the payment settles.
func TestWebhookTransientReconcileErrorDoesNotSuppressSettlement(t *testing.T) {
	t.Parallel()
	h := newHarnessFor()
	tenantID := seedHarnessTenant(t, h)

	deps := h.deps
	deps.UoW = h.store
	charges := app.NewChargeService(deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{
		TenantID: tenantID, Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}

	// The bank has settled, but the first reconcile attempt fails transiently.
	h.bank.MarkSettled(tenantID, p.TxID())
	failGets := 1
	whDeps := deps
	whDeps.Bank = flakyBank{BankProvider: h.bank, failGets: &failGets}
	wh := app.NewWebhookService(whDeps)

	ev := app.PaymentEvent{TenantID: tenantID, TxID: p.TxID(), EventKey: "evt-1"}

	// First delivery: reconcile fails → error; nothing must be marked processed.
	if err := wh.HandlePaymentEvent(context.Background(), ev); !errors.Is(err, errBankDown) {
		t.Fatalf("want transient reconcile error, got %v", err)
	}
	reloaded, _ := charges.GetPayment(context.Background(), tenantID, p.ID())
	if reloaded.Status() != payment.StatusPending {
		t.Fatal("payment must remain pending after a failed reconcile")
	}

	// Redelivery with the SAME event key: now reconcile succeeds and the payment
	// settles. Before the fix this was acked as a duplicate no-op and lost.
	if err := wh.HandlePaymentEvent(context.Background(), ev); err != nil {
		t.Fatalf("redelivery should settle: %v", err)
	}
	reloaded, _ = charges.GetPayment(context.Background(), tenantID, p.ID())
	if reloaded.Status() != payment.StatusPaid {
		t.Fatal("payment must settle on redelivery after a transient reconcile failure")
	}
}

// (c) F3a — concurrent requests with the same idempotency key reserve the key
// before charging, so exactly one bank charge and one ledger entry result.
func TestCreateChargeConcurrentSameKeyChargesOnce(t *testing.T) {
	t.Parallel()
	h := newHarnessFor()
	tenantID := seedHarnessTenant(t, h)

	deps := h.deps
	deps.UoW = h.store
	charges := app.NewChargeService(deps)
	in := app.CreateChargeInput{TenantID: tenantID, Endpoint: "pix.create", AmountCents: 4200, Currency: "BRL", IdempotencyKey: "kc"}

	const n = 8
	var wg sync.WaitGroup
	ids := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := charges.CreateCharge(context.Background(), in)
			errs[i] = err
			if p != nil {
				ids[i] = p.ID()
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d failed: %v", i, err)
		}
	}
	// Every caller resolves to the same payment.
	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("idempotency violated: id[%d]=%q != id[0]=%q", i, ids[i], ids[0])
		}
	}
	if got := h.bank.ChargeCount(); got != 1 {
		t.Fatalf("concurrent same-key requests must charge once: charge count = %d, want 1", got)
	}
	if got := h.store.LedgerLen(); got != 1 {
		t.Fatalf("concurrent same-key requests must bill once: ledger len = %d, want 1", got)
	}
}
