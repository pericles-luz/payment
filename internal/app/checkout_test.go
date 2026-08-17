package app_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// The harness fixedClock is Unix(1000); use instants on either side for expiry.
var (
	checkoutFutureExpiry = time.Unix(100000, 0).UTC()
	checkoutPastExpiry   = time.Unix(500, 0).UTC()
)

// newCheckoutHarness wires a CheckoutService with the stub as the checkout provider
// plus a seeded, priced, credentialed tenant. Returns the service, the harness, and
// the tenant id.
func newCheckoutHarness(t *testing.T) (*app.CheckoutService, *harness, string) {
	t.Helper()
	h := newHarness(t)
	h.deps.Checkout = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.CheckoutCreateEndpoint, 30); err != nil {
		t.Fatalf("price: %v", err)
	}
	return app.NewCheckoutService(h.deps), h, tn.ID()
}

func baseCheckoutInput(tenantID, idemKey string) app.CreateCheckoutSessionInput {
	return app.CreateCheckoutSessionInput{
		TenantID:         tenantID,
		Currency:         "BRL",
		ExpiresInSeconds: 3600,
		CardType:         "credit",
		IdempotencyKey:   idemKey,
		Items: []app.CheckoutItemInput{
			{Description: "Anuidade", AmountCents: 1000},
			{Description: "Taxa", AmountCents: 250},
		},
	}
}

// roteiro 9.a/9.b/9.c: open a session for each card-type / auth combination.
func TestCheckoutCreateSessionMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		cardType    string
		requireAuth bool
	}{
		{"9a_credit_no_auth", "credit", false},
		{"9b_debit", "debit", false},
		{"9c_credit_with_auth", "credit", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, h, tenantID := newCheckoutHarness(t)
			in := baseCheckoutInput(tenantID, "k-"+tc.name)
			in.CardType = tc.cardType
			in.RequireAuthentication = tc.requireAuth
			p, res, err := svc.CreateSession(context.Background(), in)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if p.Status() != payment.StatusPending || p.TxID() == "" {
				t.Fatalf("payment not created: %+v", p)
			}
			if p.Amount().Cents() != 1250 {
				t.Fatalf("total: want 1250 got %d", p.Amount().Cents())
			}
			if res.SessionID != p.ID() || res.Status != "OPEN" || res.RedirectURL == "" {
				t.Fatalf("unexpected result: %+v", res)
			}
			if res.CardType != tc.cardType || res.RequireAuthentication != tc.requireAuth {
				t.Fatalf("card echo mismatch: %+v", res)
			}
			if h.store.LedgerLen() != 1 {
				t.Fatalf("expected 1 ledger entry, got %d", h.store.LedgerLen())
			}
		})
	}
}

func TestCheckoutCreateIdempotent(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newCheckoutHarness(t)
	in := baseCheckoutInput(tenantID, "k1")

	var events int
	var mu sync.Mutex
	_ = h.bus.Subscribe(context.Background(), app.TopicPaymentCreated, func(_ context.Context, _ ports.Message) error {
		mu.Lock()
		events++
		mu.Unlock()
		return nil
	})

	p1, res1, err := svc.CreateSession(context.Background(), in)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	p2, res2, err := svc.CreateSession(context.Background(), in)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if p1.ID() != p2.ID() || res1.SessionID != res2.SessionID {
		t.Fatalf("idempotent retry returned different session: %s vs %s", res1.SessionID, res2.SessionID)
	}
	if h.store.LedgerLen() != 1 {
		t.Fatalf("idempotent retry should not bill again, got %d", h.store.LedgerLen())
	}
	mu.Lock()
	if events != 1 {
		t.Fatalf("expected 1 event, got %d", events)
	}
	mu.Unlock()
}

func TestCheckoutCreateAbsoluteExpiry(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newCheckoutHarness(t)
	in := baseCheckoutInput(tenantID, "k1")
	in.ExpiresInSeconds = 0
	in.ExpiresAt = checkoutFutureExpiry
	if _, _, err := svc.CreateSession(context.Background(), in); err != nil {
		t.Fatalf("absolute expiry: %v", err)
	}
}

func TestCheckoutCreateValidationErrors(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newCheckoutHarness(t)

	mut := func(f func(*app.CreateCheckoutSessionInput)) app.CreateCheckoutSessionInput {
		in := baseCheckoutInput(tenantID, "k1")
		f(&in)
		return in
	}
	cases := []struct {
		name string
		in   app.CreateCheckoutSessionInput
	}{
		{"empty_items", mut(func(in *app.CreateCheckoutSessionInput) { in.Items = nil })},
		{"item_negative_amount", mut(func(in *app.CreateCheckoutSessionInput) {
			in.Items = []app.CheckoutItemInput{{Description: "x", AmountCents: -1}}
		})},
		{"item_blank_desc", mut(func(in *app.CreateCheckoutSessionInput) {
			in.Items = []app.CheckoutItemInput{{Description: "  ", AmountCents: 100}}
		})},
		{"bad_currency", mut(func(in *app.CreateCheckoutSessionInput) { in.Currency = "XX" })},
		{"unknown_card_type", mut(func(in *app.CreateCheckoutSessionInput) { in.CardType = "crypto" })},
		{"missing_idem", mut(func(in *app.CreateCheckoutSessionInput) { in.IdempotencyKey = "" })},
		{"no_expiry", mut(func(in *app.CreateCheckoutSessionInput) { in.ExpiresInSeconds = 0 })},
		{"past_expiry", mut(func(in *app.CreateCheckoutSessionInput) {
			in.ExpiresInSeconds = 0
			in.ExpiresAt = checkoutPastExpiry
		})},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := svc.CreateSession(context.Background(), tc.in)
			if err == nil {
				t.Fatalf("want validation error for %s, got nil", tc.name)
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: want validation error, got %v", tc.name, err)
			}
		})
	}
}

// An item set whose running int64 sum wraps past math.MaxInt64 must be rejected
// with ErrValidation before any payment is reserved — never reserved/displayed at
// the wrapped (small positive) total. Three items (≤100) trigger the wrap.
func TestCheckoutCreateItemSumOverflow(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newCheckoutHarness(t)
	in := baseCheckoutInput(tenantID, "k-overflow")
	in.Items = []app.CheckoutItemInput{
		{Description: "a", AmountCents: math.MaxInt64},
		{Description: "b", AmountCents: math.MaxInt64},
		{Description: "c", AmountCents: 5},
	}
	_, _, err := svc.CreateSession(context.Background(), in)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for overflowing item sum, got %v", err)
	}
	if h.store.LedgerLen() != 0 {
		t.Fatalf("an overflowing total must not reserve/bill, got %d ledger entries", h.store.LedgerLen())
	}
}

func TestCheckoutCreateInactiveTenant(t *testing.T) {
	t.Parallel()
	svc, h, tenantID := newCheckoutHarness(t)
	tn, err := h.store.FindTenantByID(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("find tenant: %v", err)
	}
	tn.Deactivate()
	if err := h.store.SaveTenant(context.Background(), tn); err != nil {
		t.Fatalf("save tenant: %v", err)
	}
	if _, _, err := svc.CreateSession(context.Background(), baseCheckoutInput(tenantID, "k1")); err == nil {
		t.Fatalf("want error for inactive tenant")
	}
}

func TestCheckoutCreateUnknownTenant(t *testing.T) {
	t.Parallel()
	svc, _, _ := newCheckoutHarness(t)
	if _, _, err := svc.CreateSession(context.Background(), baseCheckoutInput("nope", "k1")); err == nil {
		t.Fatalf("want error for unknown tenant")
	}
}

// A provider failure (here: the stub rejects a tenant without a bank credential)
// must surface as an error from CreateSession (no panic, no half-billed session).
func TestCheckoutCreateBankError(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Checkout = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "NoCred")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	// Priced but intentionally no bank credential — the stub provider errors.
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.CheckoutCreateEndpoint, 30); err != nil {
		t.Fatalf("price: %v", err)
	}
	svc := app.NewCheckoutService(h.deps)
	if _, _, err := svc.CreateSession(context.Background(), baseCheckoutInput(tn.ID(), "k1")); err == nil {
		t.Fatalf("want error when the provider rejects the request")
	}
	if h.store.LedgerLen() != 0 {
		t.Fatalf("a failed provider call must not bill, got %d ledger entries", h.store.LedgerLen())
	}
}

// Concurrent opens with the same idempotency key must open/bill exactly once.
func TestCheckoutCreateConcurrentSameKey(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Checkout = h.bank
	h.deps.UoW = h.store // real transactional boundary so the unique index serialises racers
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "Acme")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	if _, err := admin.SetEndpointPrice(context.Background(), tn.ID(), app.CheckoutCreateEndpoint, 30); err != nil {
		t.Fatalf("price: %v", err)
	}
	svc := app.NewCheckoutService(h.deps)
	in := baseCheckoutInput(tn.ID(), "kc")

	const n = 8
	var wg sync.WaitGroup
	ids := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, _, err := svc.CreateSession(context.Background(), in)
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
	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("idempotency violated: id[%d]=%q != id[0]=%q", i, ids[i], ids[0])
		}
	}
	if got := h.store.LedgerLen(); got != 1 {
		t.Fatalf("concurrent same-key opens must bill once: ledger len = %d, want 1", got)
	}
}

// TestCheckoutCreateNoPriceIsFree pins the SIN-69512 charge-time contract: a
// tenant with NO configured checkout price is served for free (billed 0 cents),
// not rejected; a single 0-cent ledger entry is written.
//
// Rule-3 disclosure: this test previously required an error for the unpriced case —
// the exact behavior the CEO reframed in SIN-69508/SIN-69512. Its assertion is
// updated to the new mandated contract; CTO ratifies at the review gate.
func TestCheckoutCreateNoPriceIsFree(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.deps.Checkout = h.bank
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "NoPrice")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	h.deps.Credentials.(*secret.Store).Set(tn.ID(), ports.BankCredential{ClientID: "cid", Secret: "shh"})
	svc := app.NewCheckoutService(h.deps)
	p, _, err := svc.CreateSession(context.Background(), baseCheckoutInput(tn.ID(), "k1"))
	if err != nil {
		t.Fatalf("unpriced checkout should succeed (free), got %v", err)
	}
	if p == nil || p.TxID() == "" {
		t.Fatal("checkout not created for unpriced (free) endpoint")
	}
	// Payment reserved normally under the free contract.
	if _, err := h.store.FindPaymentByIdempotencyKey(context.Background(), tn.ID(), "k1"); err != nil {
		t.Fatalf("free create must reserve a payment, got %v", err)
	}
	entries, err := h.store.ListLedgerEntries(context.Background(), tn.ID())
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	if len(entries) != 1 || entries[0].PriceCents() != 0 {
		t.Fatalf("want 1 ledger entry billed 0 cents, got %+v", entries)
	}
}
