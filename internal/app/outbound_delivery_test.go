package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

// --- fakes -----------------------------------------------------------------

// fakeAccountResolver is a programmable app.AccountResolver.
type fakeAccountResolver struct {
	accountID string
	err       error
	gotTenant string
}

func (r *fakeAccountResolver) ResolveAccountID(_ context.Context, tenantID string) (string, error) {
	r.gotTenant = tenantID
	return r.accountID, r.err
}

// fakeTenantFinder backs the default resolver (app.NewStoreAccountResolver).
type fakeTenantFinder struct {
	t   *tenant.Tenant
	err error
}

func (f fakeTenantFinder) FindTenantByID(_ context.Context, _ string) (*tenant.Tenant, error) {
	return f.t, f.err
}

// failingQueue always errors on enqueue (best-effort swallow proof).
type failingQueue struct{}

func (failingQueue) EnqueueDelivery(_ context.Context, _ *outboundqueue.Delivery) error {
	return errors.New("boom enqueue")
}

// failingSink always errors on dead-letter.
type failingSink struct{}

func (failingSink) DeadLetter(_ context.Context, _ *outboundqueue.DeadLetter) error {
	return errors.New("boom deadletter")
}

var obNow = time.Date(2026, 8, 17, 15, 0, 0, 0, time.UTC)

func newAttributor(t *testing.T, enabled bool, resolver app.AccountResolver, store *inmemory.OutboundDeliveryStore) *app.OutboundAttributor {
	t.Helper()
	return app.NewOutboundAttributor(app.OutboundAttributorDeps{
		Enabled:     enabled,
		Resolver:    resolver,
		Queue:       store,
		DeadLetters: store,
		Clock:       fixedClock{t: obNow},
		IDs:         &seqIDs{},
	})
}

// --- tests -----------------------------------------------------------------

// A real reseller Conta ⇒ the event is enqueued on THAT Conta's outbox (A01: keyed by
// the resolved accountID), nothing dead-lettered.
func TestAttributeEnqueuesForRealConta(t *testing.T) {
	store := inmemory.NewOutboundDeliveryStore()
	res := &fakeAccountResolver{accountID: "acct-verz"}
	a := newAttributor(t, true, res, store)

	a.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid")

	if res.gotTenant != "ten-1" {
		t.Fatalf("resolver saw tenant %q, want ten-1", res.gotTenant)
	}
	got, err := store.PendingDeliveries(context.Background(), "acct-verz")
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 pending delivery, got %d", len(got))
	}
	d := got[0]
	if d.AccountID() != "acct-verz" || d.TenantID() != "ten-1" || d.EventKey() != "ek-1" ||
		d.TxID() != "tx-1" || d.EventType() != "payment.paid" {
		t.Fatalf("delivery fields wrong: %+v", d)
	}
	dls, _ := store.DeadLetters(context.Background())
	if len(dls) != 0 {
		t.Fatalf("expected no dead-letters, got %d", len(dls))
	}
}

// Cross-account isolation (A01): an event for Conta A is never visible on Conta B's
// outbox, even for an adjacent id.
func TestAttributeIsolatesByAccount(t *testing.T) {
	store := inmemory.NewOutboundDeliveryStore()
	a := newAttributor(t, true, &fakeAccountResolver{accountID: "acct-A"}, store)
	a.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid")

	other, err := store.PendingDeliveries(context.Background(), "acct-B")
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("expected 0 deliveries for acct-B, got %d (cross-account leak)", len(other))
	}
}

// Resolver error (owner INDETERMINABLE) ⇒ dead-letter, never a forward, never a
// fallback (fail-closed).
func TestAttributeDeadLettersOnResolverError(t *testing.T) {
	store := inmemory.NewOutboundDeliveryStore()
	res := &fakeAccountResolver{err: errors.New("store down")}
	a := newAttributor(t, true, res, store)

	a.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid")

	dls, err := store.DeadLetters(context.Background())
	if err != nil {
		t.Fatalf("deadletters: %v", err)
	}
	if len(dls) != 1 {
		t.Fatalf("want 1 dead-letter, got %d", len(dls))
	}
	if dls[0].Reason() != outboundqueue.ReasonUnresolvable {
		t.Fatalf("reason = %q, want unresolvable", dls[0].Reason())
	}
	if dls[0].TenantID() != "ten-1" || dls[0].EventKey() != "ek-1" {
		t.Fatalf("dead-letter fields wrong: %+v", dls[0])
	}
	// No delivery anywhere: the dead-letter is NOT keyed by any account.
	for _, acct := range []string{"", "ten-1", "acct-1"} {
		if got, _ := store.PendingDeliveries(context.Background(), acct); len(got) != 0 {
			t.Fatalf("expected no delivery for %q, got %d", acct, len(got))
		}
	}
}

// A tenant with no reseller Conta (self-account, accountID=="") ⇒ SKIP: neither
// enqueued nor dead-lettered (the normal direct-customer case is not an anomaly).
func TestAttributeSkipsSelfAccount(t *testing.T) {
	store := inmemory.NewOutboundDeliveryStore()
	a := newAttributor(t, true, &fakeAccountResolver{accountID: ""}, store)

	a.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid")

	if got, _ := store.PendingDeliveries(context.Background(), ""); len(got) != 0 {
		t.Fatalf("expected no delivery, got %d", len(got))
	}
	if dls, _ := store.DeadLetters(context.Background()); len(dls) != 0 {
		t.Fatalf("expected no dead-letter, got %d", len(dls))
	}
}

// Disabled attributor (flag off) ⇒ genuine no-op (dark default).
func TestAttributeDisabledIsNoop(t *testing.T) {
	store := inmemory.NewOutboundDeliveryStore()
	res := &fakeAccountResolver{accountID: "acct-verz"}
	a := newAttributor(t, false, res, store)

	a.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid")

	if res.gotTenant != "" {
		t.Fatalf("disabled attributor should not resolve, saw %q", res.gotTenant)
	}
	if got, _ := store.PendingDeliveries(context.Background(), "acct-verz"); len(got) != 0 {
		t.Fatalf("expected no delivery when disabled, got %d", len(got))
	}
}

// A nil attributor and a nil-port attributor are safe no-ops (half-wired deployment
// never originates a mis-attributed delivery).
func TestAttributeNilAndUnwiredAreSafe(t *testing.T) {
	var nilA *app.OutboundAttributor
	nilA.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid") // must not panic

	// Enabled but missing ports ⇒ inactive.
	half := app.NewOutboundAttributor(app.OutboundAttributorDeps{Enabled: true})
	half.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid") // must not panic
}

// Idempotency: the same inbound event attributed twice enqueues ONE delivery (dedup by
// event_key), mirroring a bank redelivery.
func TestAttributeIdempotentOnEventKey(t *testing.T) {
	store := inmemory.NewOutboundDeliveryStore()
	a := newAttributor(t, true, &fakeAccountResolver{accountID: "acct-verz"}, store)

	a.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid")
	a.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid")

	got, _ := store.PendingDeliveries(context.Background(), "acct-verz")
	if len(got) != 1 {
		t.Fatalf("want 1 delivery after duplicate, got %d", len(got))
	}
}

// Best-effort: a queue failure is swallowed (never panics, never surfaces) so the
// inbound ACK is unaffected (threat D3).
func TestAttributeSwallowsQueueError(t *testing.T) {
	a := app.NewOutboundAttributor(app.OutboundAttributorDeps{
		Enabled:     true,
		Resolver:    &fakeAccountResolver{accountID: "acct-verz"},
		Queue:       failingQueue{},
		DeadLetters: failingSink{},
		Clock:       fixedClock{t: obNow},
		IDs:         &seqIDs{},
	})
	// Must not panic or propagate.
	a.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid")
}

// Best-effort: a dead-letter sink failure is swallowed too.
func TestAttributeSwallowsDeadLetterError(t *testing.T) {
	a := app.NewOutboundAttributor(app.OutboundAttributorDeps{
		Enabled:     true,
		Resolver:    &fakeAccountResolver{err: errors.New("down")},
		Queue:       failingQueue{},
		DeadLetters: failingSink{},
		Clock:       fixedClock{t: obNow},
		IDs:         &seqIDs{},
	})
	a.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid")
}

// --- default store resolver ------------------------------------------------

func TestStoreAccountResolverReturnsParentAccount(t *testing.T) {
	tn := tenant.RehydrateWithAccount("ten-1", "Empresa", true, obNow, "acct-verz")
	r := app.NewStoreAccountResolver(fakeTenantFinder{t: tn})
	got, err := r.ResolveAccountID(context.Background(), "ten-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "acct-verz" {
		t.Fatalf("got %q, want acct-verz", got)
	}
}

func TestStoreAccountResolverSelfAccountEmpty(t *testing.T) {
	tn := tenant.Rehydrate("ten-1", "Direct", true, obNow) // no account assigned
	r := app.NewStoreAccountResolver(fakeTenantFinder{t: tn})
	got, err := r.ResolveAccountID(context.Background(), "ten-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty (self-account)", got)
	}
}

func TestStoreAccountResolverSurfacesError(t *testing.T) {
	wantErr := errors.New("store down")
	r := app.NewStoreAccountResolver(fakeTenantFinder{err: wantErr})
	_, err := r.ResolveAccountID(context.Background(), "ten-1")
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected store error surfaced, got %v", err)
	}
}

func TestStoreAccountResolverEmptyTenantNoLookup(t *testing.T) {
	r := app.NewStoreAccountResolver(fakeTenantFinder{err: errors.New("must not be called")})
	got, err := r.ResolveAccountID(context.Background(), "   ")
	if err != nil {
		t.Fatalf("empty tenant must not error, got %v", err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

// End-to-end through the default resolver: a resolver error path dead-letters via the
// real store resolver wiring.
func TestAttributeWithStoreResolverError(t *testing.T) {
	store := inmemory.NewOutboundDeliveryStore()
	resolver := app.NewStoreAccountResolver(fakeTenantFinder{err: errors.New("boom")})
	a := newAttributor(t, true, resolver, store)
	a.Attribute(context.Background(), "ten-1", "ek-1", "tx-1", "payment.paid")

	dls, _ := store.DeadLetters(context.Background())
	if len(dls) != 1 || dls[0].Reason() != outboundqueue.ReasonUnresolvable {
		t.Fatalf("expected 1 unresolvable dead-letter, got %+v", dls)
	}
}
