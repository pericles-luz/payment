package app

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

// seqIDs is a deterministic, monotonic id provider for the provisioning tests so
// each created empresa-cliente gets a distinct, predictable id.
type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (s *seqIDs) NewID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return "tid-" + strconv.Itoa(s.n)
}

// newProvSvc wires a ClientProvisioningService over a REAL in-memory tenant store
// (no DB mock — rule 5) with a deterministic clock and id provider. It returns the
// store too so tests can assert what was actually persisted.
func newProvSvc() (*ClientProvisioningService, *persistence.Store) {
	store := persistence.NewStore()
	svc := NewClientProvisioningService(store, &seqIDs{}, &akClock{now: akEpoch()})
	return svc, store
}

// TestProvisionClientBindsAccountFromKey is the happy path AND the T6 invariant at
// the use-case layer: the empresa-cliente is bound to the accountID the caller
// passed (which the HTTP adapter derives from the account-key, never the body), and
// it is actually persisted under that Account.
func TestProvisionClientBindsAccountFromKey(t *testing.T) {
	t.Parallel()
	svc, store := newProvSvc()

	cli, err := svc.ProvisionClient(context.Background(), "acct-A", "Loja X", "idem-1")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if cli.AccountID() != "acct-A" {
		t.Fatalf("account = %q, want acct-A (must come from the key)", cli.AccountID())
	}
	if cli.Name() != "Loja X" {
		t.Fatalf("name = %q, want Loja X", cli.Name())
	}
	// Persisted under that Account, readable back.
	got, err := store.FindTenantByID(context.Background(), cli.ID())
	if err != nil {
		t.Fatalf("find persisted: %v", err)
	}
	if got.AccountID() != "acct-A" {
		t.Fatalf("persisted account = %q, want acct-A", got.AccountID())
	}
}

// TestProvisionClientDefaultsName proves the optional name: an empty (or
// whitespace-only) name is accepted and defaults, since the Tenant aggregate
// requires a non-empty name.
func TestProvisionClientDefaultsName(t *testing.T) {
	t.Parallel()
	svc, _ := newProvSvc()
	for _, name := range []string{"", "   "} {
		cli, err := svc.ProvisionClient(context.Background(), "acct-A", name, "idem-"+name)
		if err != nil {
			t.Fatalf("provision (%q): %v", name, err)
		}
		if cli.Name() != defaultClientName {
			t.Fatalf("name = %q, want default %q", cli.Name(), defaultClientName)
		}
	}
}

// TestProvisionClientValidatesInputs rejects an empty account id or idempotency key
// with a validation error (defense-in-depth alongside the boundary checks).
func TestProvisionClientValidatesInputs(t *testing.T) {
	t.Parallel()
	svc, _ := newProvSvc()
	cases := []struct{ acct, idem string }{
		{"", "idem-1"},
		{"   ", "idem-1"},
		{"acct-A", ""},
		{"acct-A", "   "},
	}
	for _, c := range cases {
		_, err := svc.ProvisionClient(context.Background(), c.acct, "n", c.idem)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("acct=%q idem=%q: err = %v, want validation", c.acct, c.idem, err)
		}
	}
}

// TestProvisionClientIdempotentReplay proves the dedup contract: a repeat under the
// SAME (account, idemKey) returns the SAME empresa-cliente and does NOT create a
// duplicate, while a DIFFERENT idemKey creates a new one.
func TestProvisionClientIdempotentReplay(t *testing.T) {
	t.Parallel()
	svc, store := newProvSvc()

	first, err := svc.ProvisionClient(context.Background(), "acct-A", "Loja X", "idem-1")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	replay, err := svc.ProvisionClient(context.Background(), "acct-A", "Loja Y", "idem-1")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.ID() != first.ID() {
		t.Fatalf("replay id = %q, want same as first %q (no duplicate)", replay.ID(), first.ID())
	}
	// The replayed representation reflects the ORIGINAL create (name from the first
	// call), not the retry's differing body.
	if replay.Name() != "Loja X" {
		t.Fatalf("replay name = %q, want original Loja X", replay.Name())
	}
	// A fresh idemKey creates a distinct empresa-cliente.
	second, err := svc.ProvisionClient(context.Background(), "acct-A", "Loja Z", "idem-2")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second.ID() == first.ID() {
		t.Fatalf("fresh idemKey reused id %q", second.ID())
	}
	// Exactly two tenants were persisted (the replay did not add a third).
	all, err := store.ListTenants(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("persisted %d tenants, want 2 (replay must not duplicate)", len(all))
	}
}

// TestProvisionClientIdemKeyScopedPerAccount proves the guard is keyed by
// (account, idemKey): two DIFFERENT Accounts reusing the same idemKey each get their
// OWN empresa-cliente — one Account's idempotency window never collapses another's
// provisioning.
func TestProvisionClientIdemKeyScopedPerAccount(t *testing.T) {
	t.Parallel()
	svc, _ := newProvSvc()

	a, err := svc.ProvisionClient(context.Background(), "acct-A", "x", "shared-idem")
	if err != nil {
		t.Fatalf("acct-A: %v", err)
	}
	b, err := svc.ProvisionClient(context.Background(), "acct-B", "x", "shared-idem")
	if err != nil {
		t.Fatalf("acct-B: %v", err)
	}
	if a.ID() == b.ID() {
		t.Fatalf("cross-account idem collision: both got %q", a.ID())
	}
	if a.AccountID() != "acct-A" || b.AccountID() != "acct-B" {
		t.Fatalf("accounts crossed: a=%q b=%q", a.AccountID(), b.AccountID())
	}
}

// TestProvisionClientNilStoreFailsClosed: a service with no tenant store fails
// closed with a clear sentinel instead of panicking.
func TestProvisionClientNilStoreFailsClosed(t *testing.T) {
	t.Parallel()
	svc := NewClientProvisioningService(nil, &seqIDs{}, &akClock{now: akEpoch()})
	_, err := svc.ProvisionClient(context.Background(), "acct-A", "n", "idem-1")
	if !errors.Is(err, ErrClientProvisioningUnavailable) {
		t.Fatalf("err = %v, want ErrClientProvisioningUnavailable", err)
	}
}

// faultTenantStore is a documented test double that injects storage faults so the
// error paths (save failure; replay re-read failure) are covered without a DB mock.
// The happy-path tests use the real in-memory store (rule 5).
type faultTenantStore struct {
	saved    map[string]*tenant.Tenant
	failSave bool
	failFind bool
}

func newFaultTenantStore() *faultTenantStore {
	return &faultTenantStore{saved: make(map[string]*tenant.Tenant)}
}

var errFaultStore = errors.New("injected store fault")

func (f *faultTenantStore) SaveTenant(_ context.Context, t *tenant.Tenant) error {
	if f.failSave {
		return errFaultStore
	}
	f.saved[t.ID()] = t
	return nil
}

func (f *faultTenantStore) FindTenantByID(_ context.Context, id string) (*tenant.Tenant, error) {
	if f.failFind {
		return nil, errFaultStore
	}
	t, ok := f.saved[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

// TestProvisionClientSaveFailureSurfaces: a save fault surfaces as an error AND is
// NOT recorded in the idempotency guard, so a retry can still succeed.
func TestProvisionClientSaveFailureSurfaces(t *testing.T) {
	t.Parallel()
	store := newFaultTenantStore()
	store.failSave = true
	svc := NewClientProvisioningService(store, &seqIDs{}, &akClock{now: akEpoch()})

	if _, err := svc.ProvisionClient(context.Background(), "acct-A", "x", "idem-1"); err == nil {
		t.Fatal("want error on save fault")
	}
	// The failed create was not remembered: with the fault cleared, the same idemKey
	// succeeds (the key was not poisoned).
	store.failSave = false
	if _, err := svc.ProvisionClient(context.Background(), "acct-A", "x", "idem-1"); err != nil {
		t.Fatalf("retry after cleared fault: %v", err)
	}
}

// TestProvisionClientReplayFindFailureSurfaces: if the store errors while re-reading
// on an idempotent replay, the error surfaces (fail-closed) rather than a nil/panic.
func TestProvisionClientReplayFindFailureSurfaces(t *testing.T) {
	t.Parallel()
	store := newFaultTenantStore()
	svc := NewClientProvisioningService(store, &seqIDs{}, &akClock{now: akEpoch()})

	if _, err := svc.ProvisionClient(context.Background(), "acct-A", "x", "idem-1"); err != nil {
		t.Fatalf("first: %v", err)
	}
	store.failFind = true
	if _, err := svc.ProvisionClient(context.Background(), "acct-A", "x", "idem-1"); err == nil {
		t.Fatal("want error when replay re-read fails")
	}
}

// TestProvisionClientGuardTTLPrunes exercises the TTL prune path: after the window
// elapses, the same idemKey is treated as fresh (the guard entry was dropped).
func TestProvisionClientGuardTTLPrunes(t *testing.T) {
	t.Parallel()
	clock := &akClock{now: akEpoch()}
	store := persistence.NewStore()
	svc := NewClientProvisioningService(store, &seqIDs{}, clock)

	first, err := svc.ProvisionClient(context.Background(), "acct-A", "x", "idem-1")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	clock.advance(clientProvisionIdempotencyTTL + time.Nanosecond)
	second, err := svc.ProvisionClient(context.Background(), "acct-A", "x", "idem-1")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second.ID() == first.ID() {
		t.Fatalf("expired idemKey collapsed to the same tenant %q", second.ID())
	}
}
