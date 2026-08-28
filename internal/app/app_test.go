package app_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/messaging/inmemory"
	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fixedClock is a deterministic Clock.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// seqIDs is a deterministic IDProvider.
type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (s *seqIDs) NewID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return fmt.Sprintf("id-%d", s.n)
}

type harness struct {
	store *persistence.Store
	bank  *bank.StubProvider
	bus   *inmemory.Bus
	// creds is the concrete credential store behind deps.Credentials, exposed so a
	// test that seeds its OWN tenant (rather than reusing the pre-seeded "t1") can give
	// it a bank credential — the stub resolves one on every call.
	creds *secret.Store
	deps  app.Deps
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessFor()
}

// newHarnessFor builds a harness without requiring *testing.T. It seeds a bank
// credential for tenant id "t1" so faultRepo-backed tests (which resolve to
// "t1") can reach the stub bank.
func newHarnessFor() *harness {
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{
		"t1": {TenantID: "t1", ClientID: "cid", Secret: "shh"},
	})
	stub := bank.NewStubProvider(creds)
	bus := inmemory.NewBus()
	deps := app.Deps{
		Payments:    store,
		Tenants:     store,
		Pricing:     store,
		Ledger:      store,
		Processed:   store,
		Bus:         bus,
		Bank:        stub,
		Credentials: creds,
		Clock:       fixedClock{t: time.Unix(1000, 0).UTC()},
		IDs:         &seqIDs{},
	}
	return &harness{store: store, bank: stub, bus: bus, creds: creds, deps: deps}
}

func TestAdminCreateTenant(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tn.ID() == "" || tn.Name() != "Acme" {
		t.Fatal("bad tenant")
	}
	if _, err := admin.CreateTenant(context.Background(), " "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation, got %v", err)
	}
}

func TestAdminSetPrice(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	admin := app.NewAdminService(h.deps)
	if _, err := admin.SetEndpointPrice(context.Background(), "missing", "pix.create", 10); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found for missing tenant, got %v", err)
	}
	tn, _ := admin.CreateTenant(context.Background(), "Acme")
	p, err := admin.SetEndpointPrice(context.Background(), tn.ID(), "pix.create", 75)
	if err != nil {
		t.Fatalf("set price: %v", err)
	}
	if p.PriceCents() != 75 {
		t.Fatal("price mismatch")
	}
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), "", 75); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation, got %v", err)
	}
}

func TestCreateChargeAndBilling(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	admin := app.NewAdminService(h.deps)
	tn, _ := admin.CreateTenant(context.Background(), "Acme")
	h.store.SaveTenant(context.Background(), tn) // ensure persisted (already is)
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), "pix.create", 99); err != nil {
		t.Fatalf("price: %v", err)
	}

	// Subscribe to capture the published event.
	var got int
	var mu sync.Mutex
	_ = h.bus.Subscribe(context.Background(), app.TopicPaymentCreated, func(_ context.Context, m ports.Message) error {
		mu.Lock()
		got++
		mu.Unlock()
		if m.TenantID != tn.ID() {
			t.Errorf("event tenant mismatch")
		}
		return nil
	})

	charges := app.NewChargeService(h.deps)
	in := app.CreateChargeInput{TenantID: tn.ID(), Endpoint: "pix.create", AmountCents: 5000, Currency: "BRL", IdempotencyKey: "k1"}
	p, err := charges.CreateCharge(context.Background(), in)
	if err != nil {
		t.Fatalf("create charge: %v", err)
	}
	if p.Status() != payment.StatusPending || p.TxID() == "" {
		t.Fatal("charge not created properly")
	}
	if h.store.LedgerLen() != 1 {
		t.Fatalf("expected 1 ledger entry, got %d", h.store.LedgerLen())
	}
	mu.Lock()
	if got != 1 {
		t.Fatalf("expected 1 published event, got %d", got)
	}
	mu.Unlock()

	// Idempotent retry: same key returns same payment, no new ledger entry/event.
	p2, err := charges.CreateCharge(context.Background(), in)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if p2.ID() != p.ID() {
		t.Fatal("idempotency violated: different payment id")
	}
	if h.store.LedgerLen() != 1 {
		t.Fatalf("idempotent retry should not bill again, got %d", h.store.LedgerLen())
	}
}

func TestCreateChargeErrors(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	charges := app.NewChargeService(h.deps)

	// Unknown tenant.
	_, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{TenantID: "nope", Endpoint: "pix.create", AmountCents: 10, Currency: "BRL", IdempotencyKey: "k"})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}

	admin := app.NewAdminService(h.deps)
	tn, _ := admin.CreateTenant(context.Background(), "Acme")
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})

	// Missing idempotency key.
	if _, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{TenantID: tn.ID(), Endpoint: "pix.create", AmountCents: 10, Currency: "BRL"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation for missing idem, got %v", err)
	}

	// Endpoint not priced → free (SIN-69512): served, billed 0 cents, NOT rejected.
	// (Rule-3 disclosure: this sub-assertion previously required ErrNotFound; the
	// mandated charge-time contract changed it to success. CTO ratifies at the gate.)
	if _, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{TenantID: tn.ID(), Endpoint: "unpriced", AmountCents: 10, Currency: "BRL", IdempotencyKey: "kfree"}); err != nil {
		t.Fatalf("unpriced endpoint should succeed (free), got %v", err)
	}
	freeEntries, _ := h.store.ListLedgerEntries(context.Background(), tn.ID())
	var sawFree bool
	for _, e := range freeEntries {
		if e.Endpoint() == "unpriced" {
			sawFree = true
			if e.PriceCents() != 0 {
				t.Fatalf("unpriced endpoint must bill 0 cents, got %d", e.PriceCents())
			}
		}
	}
	if !sawFree {
		t.Fatal("expected a 0-cent ledger entry for the unpriced endpoint")
	}

	// Bad money.
	_, _ = admin.SetEndpointPrice(context.Background(), tn.ID(), "pix.create", 10)
	if _, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{TenantID: tn.ID(), Endpoint: "pix.create", AmountCents: 0, Currency: "BRL", IdempotencyKey: "k2"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want validation for zero amount, got %v", err)
	}
}

func TestGetPaymentTenantScoping(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	admin := app.NewAdminService(h.deps)
	tn, _ := admin.CreateTenant(context.Background(), "Acme")
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	_, _ = admin.SetEndpointPrice(context.Background(), tn.ID(), "pix.create", 10)
	charges := app.NewChargeService(h.deps)
	p, err := charges.CreateCharge(context.Background(), app.CreateChargeInput{TenantID: tn.ID(), Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Owner can read.
	if _, err := charges.GetPayment(context.Background(), tn.ID(), p.ID()); err != nil {
		t.Fatalf("owner read: %v", err)
	}
	// Another tenant cannot (IDOR protection): not found.
	if _, err := charges.GetPayment(context.Background(), "other", p.ID()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want not found cross-tenant, got %v", err)
	}
}

func TestWebhookReconciliationAndReplay(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	admin := app.NewAdminService(h.deps)
	tn, _ := admin.CreateTenant(context.Background(), "Acme")
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	_, _ = admin.SetEndpointPrice(context.Background(), tn.ID(), "pix.create", 10)
	charges := app.NewChargeService(h.deps)
	p, _ := charges.CreateCharge(context.Background(), app.CreateChargeInput{TenantID: tn.ID(), Endpoint: "pix.create", AmountCents: 100, Currency: "BRL", IdempotencyKey: "k"})

	wh := app.NewWebhookService(h.deps)

	// Before bank settles: reconciliation says pending → no settlement.
	if err := wh.HandlePaymentEvent(context.Background(), app.PaymentEvent{TenantID: tn.ID(), TxID: p.TxID(), EventKey: "e1"}); err != nil {
		t.Fatalf("webhook pending: %v", err)
	}
	reloaded, _ := charges.GetPayment(context.Background(), tn.ID(), p.ID())
	if reloaded.Status() != payment.StatusPending {
		t.Fatal("should still be pending before bank settles")
	}

	// Bank settles; a new event reconciles to paid.
	h.bank.MarkSettled(tn.ID(), p.TxID())
	if err := wh.HandlePaymentEvent(context.Background(), app.PaymentEvent{TenantID: tn.ID(), TxID: p.TxID(), EventKey: "e2"}); err != nil {
		t.Fatalf("webhook settle: %v", err)
	}
	reloaded, _ = charges.GetPayment(context.Background(), tn.ID(), p.ID())
	if reloaded.Status() != payment.StatusPaid {
		t.Fatal("should be paid after reconciliation")
	}

	// Replay of e2 is a no-op (idempotent), payment stays paid.
	if err := wh.HandlePaymentEvent(context.Background(), app.PaymentEvent{TenantID: tn.ID(), TxID: p.TxID(), EventKey: "e2"}); err != nil {
		t.Fatalf("replay: %v", err)
	}
}

func TestWebhookValidation(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	wh := app.NewWebhookService(h.deps)
	cases := []app.PaymentEvent{
		{TenantID: "", TxID: "tx", EventKey: "e"},
		{TenantID: "t", TxID: "", EventKey: "e"},
		{TenantID: "t", TxID: "tx", EventKey: ""},
	}
	for i, c := range cases {
		if err := wh.HandlePaymentEvent(context.Background(), c); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("case %d: want validation, got %v", i, err)
		}
	}
}
