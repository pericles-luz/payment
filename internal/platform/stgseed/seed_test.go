package stgseed_test

import (
	"context"
	"errors"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/platform/stgseed"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// fixedClock returns a constant time so ledger timestamps and the invoice window
// are deterministic across a test run.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// seqIDs hands out predictable ids so a duplicated call (bug) would collide.
type seqIDs struct{ n int }

func (s *seqIDs) NewID() string {
	s.n++
	return "id-" + itoa(s.n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// newDeps builds a seeder over a real in-memory store (no DB mock, per quality
// bar rule 5) wired with a full account/invoice-capable console.
func newDeps() (stgseed.Deps, *persistence.Store) {
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	console := app.NewConsoleService(app.ConsoleDeps{
		Tenants:    store,
		Accounts:   store,
		Pricing:    store,
		Ledger:     store,
		Invoices:   store,
		Audit:      store,
		CredWriter: creds,
		CredReader: creds,
		Clock:      fixedClock{t: time.Unix(1_700_000_000, 0).UTC()},
		IDs:        &seqIDs{},
	})
	return stgseed.Deps{
		Console:  console,
		Accounts: store,
		Tenants:  store,
		Ledger:   store,
		Clock:    fixedClock{t: time.Unix(1_700_000_000, 0).UTC()},
		IDs:      &seqIDs{},
	}, store
}

func TestApply_Disabled_NoOp(t *testing.T) {
	t.Parallel()
	deps, store := newDeps()
	res, err := stgseed.Apply(context.Background(), stgseed.Config{Enabled: false, StubMode: true}, deps)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Applied {
		t.Fatalf("expected no-op when disabled, got applied")
	}
	if res.SkipReason == "" {
		t.Fatalf("expected a skip reason")
	}
	assertEmpty(t, store)
}

func TestApply_NotStub_NoOp(t *testing.T) {
	t.Parallel()
	deps, store := newDeps()
	res, err := stgseed.Apply(context.Background(), stgseed.Config{Enabled: true, StubMode: false}, deps)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Applied {
		t.Fatalf("expected no-op when not stub, got applied")
	}
	if res.SkipReason != "not stub mode (PAYMENT_C6_BASE_URL set)" {
		t.Fatalf("unexpected reason: %q", res.SkipReason)
	}
	assertEmpty(t, store)
}

func TestApply_EnabledStub_Seeds(t *testing.T) {
	t.Parallel()
	deps, store := newDeps()
	res, err := stgseed.Apply(context.Background(), stgseed.Config{Enabled: true, StubMode: true}, deps)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.Applied {
		t.Fatalf("expected seed applied, got skip: %q", res.SkipReason)
	}
	if res.AccountID == "" {
		t.Fatalf("expected an account id")
	}
	if res.Tenants != 2 {
		t.Fatalf("expected 2 tenants, got %d", res.Tenants)
	}
	// 2 tenants × (3 pix + 2 checkout) = 10 ledger entries.
	if res.Entries != 10 {
		t.Fatalf("expected 10 ledger entries, got %d", res.Entries)
	}
	if res.Invoices != 2 {
		t.Fatalf("expected 2 invoices (one per tenant with consumption), got %d", res.Invoices)
	}

	// The account is real (not a derived self-account) and named Verz.
	accts, err := store.ListAccounts(context.Background())
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	if len(accts) != 1 || accts[0].Name() != "Verz" {
		t.Fatalf("expected one account 'Verz', got %+v", accts)
	}

	// Every seeded tenant is bound to the Verz account and carries consumption
	// attributed to that account in the ledger.
	tenants, err := store.ListTenants(context.Background())
	if err != nil {
		t.Fatalf("list tenants: %v", err)
	}
	if len(tenants) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(tenants))
	}
	byAccount, err := store.ListLedgerEntriesByAccount(context.Background(), res.AccountID)
	if err != nil {
		t.Fatalf("list ledger by account: %v", err)
	}
	if len(byAccount) != 10 {
		t.Fatalf("expected 10 account-attributed ledger entries, got %d", len(byAccount))
	}
	assertOnlySeedEndpoints(t, byAccount)
}

func TestApply_Idempotent_SecondBootNoOp(t *testing.T) {
	t.Parallel()
	deps, store := newDeps()
	cfg := stgseed.Config{Enabled: true, StubMode: true}

	first, err := stgseed.Apply(context.Background(), cfg, deps)
	if err != nil || !first.Applied {
		t.Fatalf("first apply should seed: applied=%v err=%v", first.Applied, err)
	}

	// Second boot over the same (now-populated) store: no-op, no duplication.
	second, err := stgseed.Apply(context.Background(), cfg, deps)
	if err != nil {
		t.Fatalf("unexpected err on second apply: %v", err)
	}
	if second.Applied {
		t.Fatalf("expected idempotent no-op on second boot, got applied")
	}
	if second.SkipReason != "store not empty" {
		t.Fatalf("unexpected reason: %q", second.SkipReason)
	}

	accts, _ := store.ListAccounts(context.Background())
	if len(accts) != 1 {
		t.Fatalf("expected still exactly one account after second boot, got %d", len(accts))
	}
	tenants, _ := store.ListTenants(context.Background())
	if len(tenants) != 2 {
		t.Fatalf("expected still exactly two tenants after second boot, got %d", len(tenants))
	}
}

func TestApply_StoreWithExistingTenant_NoOp(t *testing.T) {
	t.Parallel()
	deps, store := newDeps()
	// Pre-existing data (e.g. a real tenant) must block the seed even on a stub.
	if _, err := deps.Console.CreateTenant(context.Background(), "Pre-existing"); err != nil {
		t.Fatalf("seed pre-existing tenant: %v", err)
	}
	res, err := stgseed.Apply(context.Background(), stgseed.Config{Enabled: true, StubMode: true}, deps)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Applied {
		t.Fatalf("expected no-op when store already has a tenant")
	}
	accts, _ := store.ListAccounts(context.Background())
	if len(accts) != 0 {
		t.Fatalf("seed must not create accounts when store non-empty, got %d", len(accts))
	}
}

func TestApply_ListError_Propagates(t *testing.T) {
	t.Parallel()
	deps, _ := newDeps()
	deps.Accounts = failingAccountLister{}
	_, err := stgseed.Apply(context.Background(), stgseed.Config{Enabled: true, StubMode: true}, deps)
	if err == nil {
		t.Fatalf("expected error to propagate from account listing")
	}
}

func TestApply_TenantListError_Propagates(t *testing.T) {
	t.Parallel()
	deps, _ := newDeps()
	deps.Tenants = failingTenantLister{}
	_, err := stgseed.Apply(context.Background(), stgseed.Config{Enabled: true, StubMode: true}, deps)
	if err == nil {
		t.Fatalf("expected error to propagate from tenant listing")
	}
}

func TestApply_LedgerAppendError_Propagates(t *testing.T) {
	t.Parallel()
	deps, _ := newDeps()
	deps.Ledger = failingLedger{}
	_, err := stgseed.Apply(context.Background(), stgseed.Config{Enabled: true, StubMode: true}, deps)
	if err == nil {
		t.Fatalf("expected error to propagate from ledger append")
	}
}

type failingAccountLister struct{}

func (failingAccountLister) ListAccounts(context.Context) ([]*account.Account, error) {
	return nil, errBoom
}

type failingTenantLister struct{}

func (failingTenantLister) ListTenants(context.Context) ([]*tenant.Tenant, error) {
	return nil, errBoom
}

type failingLedger struct{}

func (failingLedger) AppendLedgerEntry(context.Context, billing.LedgerEntry) error {
	return errBoom
}

var errBoom = errors.New("boom")

func assertEmpty(t *testing.T, store *persistence.Store) {
	t.Helper()
	if a, _ := store.ListAccounts(context.Background()); len(a) != 0 {
		t.Fatalf("expected no accounts, got %d", len(a))
	}
	if tn, _ := store.ListTenants(context.Background()); len(tn) != 0 {
		t.Fatalf("expected no tenants, got %d", len(tn))
	}
}

func assertOnlySeedEndpoints(t *testing.T, entries []billing.LedgerEntry) {
	t.Helper()
	for _, e := range entries {
		switch e.Endpoint() {
		case app.PixCreateEndpoint, app.CheckoutCreateEndpoint:
		default:
			t.Fatalf("unexpected seeded endpoint %q", e.Endpoint())
		}
	}
}
