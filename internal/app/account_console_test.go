package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newAccountConsole builds a ConsoleService wired with the account plane + the
// invoice store over a real in-memory store (no DB mock). Clock is fixed so the
// created-at ordering is deterministic per the seqIDs sequence.
func newAccountConsole() (*app.ConsoleService, *persistence.Store) {
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:    store,
		Accounts:   store,
		Pricing:    store,
		Ledger:     store,
		Invoices:   store,
		Audit:      store,
		CredWriter: creds,
		CredReader: creds,
		Clock:      fixedClock{t: time.Unix(9000, 0).UTC()},
		IDs:        &seqIDs{},
	})
	return svc, store
}

// seedAccount persists an account with a concrete created time so list ordering
// and self/real classification can be asserted.
func seedAccount(t *testing.T, store *persistence.Store, id, name string, active bool, createdUnix int64) {
	t.Helper()
	a := account.Rehydrate(id, name, active, time.Unix(createdUnix, 0).UTC())
	if err := store.SaveAccount(context.Background(), a); err != nil {
		t.Fatalf("seed account: %v", err)
	}
}

func TestConsoleCreateAccount(t *testing.T) {
	t.Parallel()
	svc, store := newAccountConsole()
	ctx := context.Background()

	a, err := svc.CreateAccount(ctx, "  Verz  ")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.Name() != "Verz" || !a.Active() {
		t.Fatalf("account = %+v", a)
	}
	// A real account never carries the self-account prefix.
	if account.IsSelfAccountID(a.ID()) {
		t.Fatalf("real account id %q must not be a self-account", a.ID())
	}
	got, err := store.FindAccountByID(ctx, a.ID())
	if err != nil || got.Name() != "Verz" {
		t.Fatalf("persisted = %+v, %v", got, err)
	}

	// Blank name is a validation error surfaced to the boundary.
	if _, err := svc.CreateAccount(ctx, "   "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank name err = %v", err)
	}
}

func TestConsoleListAccounts_FilterSelfSearchStatus(t *testing.T) {
	t.Parallel()
	svc, store := newAccountConsole()
	ctx := context.Background()

	// Two real accounts + one backfilled self-account (legacy 1:1).
	seedAccount(t, store, "real-verz", "Verz Pagamentos", true, 100)
	seedAccount(t, store, "real-acme", "Acme SA", false, 300)
	seedAccount(t, store, "acct-legacy1", "Legacy Co", true, 200)

	// Tenants: two under Verz, one legacy tenant (self-account), all count.
	seedTenant(t, store, "t1", "Cliente 1", true, 10)
	seedTenant(t, store, "t2", "Cliente 2", true, 20)
	if err := bindTenant(store, "t1", "real-verz"); err != nil {
		t.Fatal(err)
	}
	if err := bindTenant(store, "t2", "real-verz"); err != nil {
		t.Fatal(err)
	}
	seedTenant(t, store, "legacy1", "Legacy Tenant", true, 30) // self-account acct-legacy1... (empty owner)

	// Default: self-accounts hidden — only the two real accounts, newest-first.
	def, err := svc.ListAccounts(ctx, app.ListAccountsQuery{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(def) != 2 || def[0].Account.ID() != "real-acme" || def[1].Account.ID() != "real-verz" {
		t.Fatalf("default list = %+v", def)
	}
	// Verz owns 2 empresas-clientes.
	if def[1].TenantCount != 2 {
		t.Fatalf("verz tenant count = %d, want 2", def[1].TenantCount)
	}

	// IncludeSelf surfaces the legacy self-account too.
	all, err := svc.ListAccounts(ctx, app.ListAccountsQuery{IncludeSelf: true})
	if err != nil || len(all) != 3 {
		t.Fatalf("include-self list = %d, %v", len(all), err)
	}

	// Status filter (real accounts only): active = Verz, suspended = Acme.
	act, _ := svc.ListAccounts(ctx, app.ListAccountsQuery{Status: app.StatusActive})
	if len(act) != 1 || act[0].Account.ID() != "real-verz" {
		t.Fatalf("active filter = %+v", act)
	}
	susp, _ := svc.ListAccounts(ctx, app.ListAccountsQuery{Status: app.StatusSuspended})
	if len(susp) != 1 || susp[0].Account.ID() != "real-acme" {
		t.Fatalf("suspended filter = %+v", susp)
	}

	// Case-insensitive name search.
	found, _ := svc.ListAccounts(ctx, app.ListAccountsQuery{Search: "verz"})
	if len(found) != 1 || found[0].Account.ID() != "real-verz" {
		t.Fatalf("search = %+v", found)
	}
}

func TestConsoleGetAccount(t *testing.T) {
	t.Parallel()
	svc, store := newAccountConsole()
	ctx := context.Background()
	seedAccount(t, store, "a1", "Verz", true, 100)

	got, err := svc.GetAccount(ctx, " a1 ")
	if err != nil || got.Name() != "Verz" {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if _, err := svc.GetAccount(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing err = %v", err)
	}
}

func TestConsoleCreateTenantUnderAccount_AndIsolation(t *testing.T) {
	t.Parallel()
	svc, store := newAccountConsole()
	ctx := context.Background()
	seedAccount(t, store, "acct-A", "Account A", true, 100)
	seedAccount(t, store, "acct-B", "Account B", true, 100)

	ta, err := svc.CreateTenantUnderAccount(ctx, "acct-A", "Cliente A1")
	if err != nil {
		t.Fatalf("create under A: %v", err)
	}
	if ta.AccountID() != "acct-A" {
		t.Fatalf("owner = %q, want acct-A", ta.AccountID())
	}
	tb, _ := svc.CreateTenantUnderAccount(ctx, "acct-B", "Cliente B1")

	// ListTenantsByAccount is account-scoped: A sees only its tenant, never B's.
	listA, err := svc.ListTenantsByAccount(ctx, "acct-A")
	if err != nil || len(listA) != 1 || listA[0].ID() != ta.ID() {
		t.Fatalf("list A = %+v, %v", listA, err)
	}
	listB, _ := svc.ListTenantsByAccount(ctx, "acct-B")
	if len(listB) != 1 || listB[0].ID() != tb.ID() {
		t.Fatalf("list B = %+v", listB)
	}

	// A missing account rejects the create (404-style resolve error).
	if _, err := svc.CreateTenantUnderAccount(ctx, "nope", "X"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing-account create err = %v", err)
	}
	// A blank name is a validation error.
	if _, err := svc.CreateTenantUnderAccount(ctx, "acct-A", "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank name err = %v", err)
	}
	// A blank account id on the listing is a validation error (no unscoped scan).
	if _, err := svc.ListTenantsByAccount(ctx, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank list err = %v", err)
	}
}

func TestConsoleListTenantsByAccount_LegacySelfAccount(t *testing.T) {
	t.Parallel()
	svc, store := newAccountConsole()
	ctx := context.Background()
	// A flat legacy tenant (empty owner) resolves to its derived self-account.
	seedTenant(t, store, "legacy", "Legacy", true, 10)
	self := account.SelfAccountID("legacy")
	list, err := svc.ListTenantsByAccount(ctx, self)
	if err != nil || len(list) != 1 || list[0].ID() != "legacy" {
		t.Fatalf("self-account list = %+v, %v", list, err)
	}
}

func TestConsoleSuspendActivateAccount(t *testing.T) {
	t.Parallel()
	svc, store := newAccountConsole()
	ctx := context.Background()
	seedAccount(t, store, "a1", "Verz", true, 100)

	a, err := svc.SuspendAccount(ctx, "a1")
	if err != nil || a.Active() {
		t.Fatalf("suspend = %+v, %v", a, err)
	}
	a, err = svc.ActivateAccount(ctx, "a1")
	if err != nil || !a.Active() {
		t.Fatalf("activate = %+v, %v", a, err)
	}
	if _, err := svc.SuspendAccount(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing suspend err = %v", err)
	}
}

func TestConsoleAccountInvoices_ListAndBatchGenerate(t *testing.T) {
	t.Parallel()
	svc, store := newAccountConsole()
	ctx := context.Background()
	seedAccount(t, store, "acct-A", "Account A", true, 100)
	seedAccount(t, store, "acct-B", "Account B", true, 100)

	// Two empresas-clientes under A; one has consumption, one has none.
	t1, _ := svc.CreateTenantUnderAccount(ctx, "acct-A", "Cliente Ativo")
	t2, _ := svc.CreateTenantUnderAccount(ctx, "acct-A", "Cliente Sem Uso")
	// One under B (isolation control) with consumption.
	tb, _ := svc.CreateTenantUnderAccount(ctx, "acct-B", "Cliente B")

	appendLedgerAt(t, store, t1.ID(), "POST /v1/charges", 250, aug(3))
	appendLedgerAt(t, store, t1.ID(), "POST /v1/charges", 250, aug(4))
	appendLedgerAt(t, store, tb.ID(), "POST /v1/charges", 900, aug(3))

	rng := app.ConsumptionRange{Start: aug(1), End: aug(6)}
	gen, err := svc.GenerateAccountInvoices(ctx, "acct-A", rng)
	if err != nil {
		t.Fatalf("batch generate: %v", err)
	}
	// Only t1 had consumption — t2 (zero) is skipped, no empty invoice.
	if len(gen) != 1 || gen[0].TenantID() != t1.ID() || gen[0].TotalCents() != 500 {
		t.Fatalf("generated = %+v", gen)
	}
	_ = t2

	// ListInvoicesByAccount returns A's invoices only (never B's).
	listA, err := svc.ListInvoicesByAccount(ctx, "acct-A")
	if err != nil || len(listA) != 1 || listA[0].TenantID() != t1.ID() {
		t.Fatalf("list A = %+v, %v", listA, err)
	}
	// B's invoice was never generated here; list is empty (isolation holds).
	listB, _ := svc.ListInvoicesByAccount(ctx, "acct-B")
	if len(listB) != 0 {
		t.Fatalf("list B = %+v, want empty", listB)
	}

	// Regenerating is append-only: a second batch adds another invoice for t1.
	gen2, _ := svc.GenerateAccountInvoices(ctx, "acct-A", rng)
	if len(gen2) != 1 {
		t.Fatalf("second batch = %+v", gen2)
	}
	listA2, _ := svc.ListInvoicesByAccount(ctx, "acct-A")
	if len(listA2) != 2 {
		t.Fatalf("append-only list = %d, want 2", len(listA2))
	}

	// An unbounded window is rejected (an invoice bills a definite period).
	if _, err := svc.GenerateAccountInvoices(ctx, "acct-A", app.ConsumptionRange{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unbounded batch err = %v", err)
	}
	// A missing account rejects both paths.
	if _, err := svc.ListInvoicesByAccount(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing list err = %v", err)
	}
	if _, err := svc.GenerateAccountInvoices(ctx, "missing", rng); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing batch err = %v", err)
	}
}

// TestGenerateAccountInvoices_IdempotencyGuard proves the double-submit guard
// (SIN-69184): a batch generation carrying an idempotency token, resubmitted with
// the SAME token, returns the FIRST submission's invoices instead of appending
// duplicate Faturas — while a FRESH token (a deliberate regeneration) still
// appends, preserving the append-only invariant (SIN-69121).
func TestGenerateAccountInvoices_IdempotencyGuard(t *testing.T) {
	t.Parallel()
	svc, store := newAccountConsole()
	ctx := context.Background()
	seedAccount(t, store, "acct-A", "Account A", true, 100)
	t1, _ := svc.CreateTenantUnderAccount(ctx, "acct-A", "Cliente Ativo")
	appendLedgerAt(t, store, t1.ID(), "POST /v1/charges", 250, aug(3))

	rng := app.ConsumptionRange{Start: aug(1), End: aug(6)}

	// First submit with token "tok-1" generates one invoice for t1.
	gen1, err := svc.GenerateAccountInvoices(ctx, "acct-A", rng, app.WithIdempotencyKey("tok-1"))
	if err != nil || len(gen1) != 1 {
		t.Fatalf("first submit = %+v, %v", gen1, err)
	}
	// Double-submit with the SAME token returns the SAME invoice ids, generating
	// nothing new — no duplicate Fatura.
	gen2, err := svc.GenerateAccountInvoices(ctx, "acct-A", rng, app.WithIdempotencyKey("tok-1"))
	if err != nil {
		t.Fatalf("replay err: %v", err)
	}
	if len(gen2) != 1 || gen2[0].ID() != gen1[0].ID() {
		t.Fatalf("replay must return first invoices, got %+v (want id %s)", gen2, gen1[0].ID())
	}
	list, _ := svc.ListInvoicesByAccount(ctx, "acct-A")
	if len(list) != 1 {
		t.Fatalf("double-submit appended a duplicate: list = %d, want 1", len(list))
	}

	// A FRESH token is a deliberate regeneration and appends (append-only stands).
	gen3, err := svc.GenerateAccountInvoices(ctx, "acct-A", rng, app.WithIdempotencyKey("tok-2"))
	if err != nil || len(gen3) != 1 || gen3[0].ID() == gen1[0].ID() {
		t.Fatalf("fresh token must append a new invoice, got %+v, %v", gen3, err)
	}
	if list, _ := svc.ListInvoicesByAccount(ctx, "acct-A"); len(list) != 2 {
		t.Fatalf("append-only after fresh token: list = %d, want 2", len(list))
	}

	// An EMPTY token disables the guard entirely — the bare call path is unchanged
	// (this is why the existing append-only test keeps passing).
	if g, err := svc.GenerateAccountInvoices(ctx, "acct-A", rng, app.WithIdempotencyKey("  ")); err != nil || len(g) != 1 {
		t.Fatalf("empty token must generate normally, got %+v, %v", g, err)
	}
	if list, _ := svc.ListInvoicesByAccount(ctx, "acct-A"); len(list) != 3 {
		t.Fatalf("empty token appended: list = %d, want 3", len(list))
	}
}

// TestConsoleAccountsUnavailable proves the account use-cases fail closed when the
// console is wired without an AccountStore (a production misconfiguration).
func TestConsoleAccountsUnavailable(t *testing.T) {
	t.Parallel()
	store := persistence.NewStore()
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants: store,
		Ledger:  store,
		Clock:   fixedClock{t: time.Unix(1, 0).UTC()},
		IDs:     &seqIDs{},
	})
	ctx := context.Background()
	if _, err := svc.ListAccounts(ctx, app.ListAccountsQuery{}); !errors.Is(err, app.ErrAccountsUnavailable) {
		t.Fatalf("list err = %v", err)
	}
	if _, err := svc.CreateAccount(ctx, "X"); !errors.Is(err, app.ErrAccountsUnavailable) {
		t.Fatalf("create err = %v", err)
	}
	if _, err := svc.GetAccount(ctx, "x"); !errors.Is(err, app.ErrAccountsUnavailable) {
		t.Fatalf("get err = %v", err)
	}
	if _, err := svc.CreateTenantUnderAccount(ctx, "x", "y"); !errors.Is(err, app.ErrAccountsUnavailable) {
		t.Fatalf("create-tenant err = %v", err)
	}
	if _, err := svc.SuspendAccount(ctx, "x"); !errors.Is(err, app.ErrAccountsUnavailable) {
		t.Fatalf("suspend err = %v", err)
	}
}

// TestConsoleAccountConsumption_ExistenceCheck pins the SIN-69506 contract at the
// use-case layer: a VALID account with zero ledger entries is a 200-shaped empty
// report (TotalCents=0), never a 404 — while a NONEXISTENT account wraps
// ErrNotFound so the screen 404s and account enumeration stays closed. The check
// lives inside AccountConsumptionInRange (mirroring ConsumptionInRange for tenants)
// so every caller — page, filter-swap partial, CSV export — inherits it.
func TestConsoleAccountConsumption_ExistenceCheck(t *testing.T) {
	t.Parallel()
	svc, store := newAccountConsole()
	ctx := context.Background()

	// A valid, seeded account that has never billed a single call.
	seedAccount(t, store, "verz-1", "Verz Pagamentos", true, 100)

	rep, err := svc.AccountConsumptionInRange(ctx, "verz-1", app.ConsumptionRange{})
	if err != nil {
		t.Fatalf("valid account with zero records must not error: %v", err)
	}
	if rep.AccountID != "verz-1" || rep.TotalCalls != 0 || rep.TotalCents != 0 || len(rep.Tenants) != 0 {
		t.Fatalf("zero-records report = %+v, want empty totals for verz-1", rep)
	}

	// AccountConsumption (unbounded convenience) behaves identically.
	if r2, err := svc.AccountConsumption(ctx, "verz-1"); err != nil || r2.TotalCents != 0 {
		t.Fatalf("AccountConsumption zero-records = %+v, %v", r2, err)
	}

	// A nonexistent account resolves to ErrNotFound (handler maps to 404) — the
	// existence check now runs inside the use-case, not only at the handler.
	if _, err := svc.AccountConsumptionInRange(ctx, "ghost", app.ConsumptionRange{}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("nonexistent account err = %v, want ErrNotFound", err)
	}

	// Once the account bills something, the report reflects it (guard didn't
	// swallow real data).
	appendLedgerAcct(t, store, "verz-1", "t1", "POST /v1/charges", 250, 1)
	if rep, err := svc.AccountConsumptionInRange(ctx, "verz-1", app.ConsumptionRange{}); err != nil || rep.TotalCents != 250 {
		t.Fatalf("with one entry = %+v, %v, want 250 cents", rep, err)
	}
}

// bindTenant re-parents a seeded tenant to an owning account by rehydrating it with
// the owner (mirrors what CreateTenantUnderAccount persists), for list-count setup.
func bindTenant(store *persistence.Store, tenantID, accountID string) error {
	ctx := context.Background()
	t, err := store.FindTenantByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := t.AssignAccount(accountID); err != nil {
		return err
	}
	return store.SaveTenant(ctx, t)
}
