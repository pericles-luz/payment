package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// newConsole builds a ConsoleService over a real in-memory store (no DB mock:
// the store enforces the same tenant-scope/idempotency invariants as SQLite).
func newConsole() (*app.ConsoleService, *persistence.Store, *secret.Store) {
	store := persistence.NewStore()
	creds := secret.NewStore(map[string]ports.BankCredential{})
	svc := app.NewConsoleService(app.ConsoleDeps{
		Tenants:    store,
		Pricing:    store,
		Ledger:     store,
		CredWriter: creds,
		Clock:      fixedClock{t: time.Unix(1000, 0).UTC()},
		IDs:        &seqIDs{},
	})
	return svc, store, creds
}

func seedTenant(t *testing.T, store *persistence.Store, id, name string, active bool, createdUnix int64) {
	t.Helper()
	ten := tenant.Rehydrate(id, name, active, time.Unix(createdUnix, 0).UTC())
	if err := store.SaveTenant(context.Background(), ten); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
}

func TestConsoleListTenants_OrderSearchAndStatus(t *testing.T) {
	t.Parallel()
	svc, store, _ := newConsole()
	ctx := context.Background()
	seedTenant(t, store, "a", "Alpha Ltda", true, 100)
	seedTenant(t, store, "b", "Bravo SA", false, 300)
	seedTenant(t, store, "c", "Charlie ME", true, 200)

	// Newest-first by createdAt.
	all, err := svc.ListTenants(ctx, app.ListTenantsQuery{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	gotOrder := []string{all[0].ID(), all[1].ID(), all[2].ID()}
	want := []string{"b", "c", "a"}
	for i := range want {
		if gotOrder[i] != want[i] {
			t.Fatalf("order = %v, want %v", gotOrder, want)
		}
	}

	// Status filter.
	active, err := svc.ListTenants(ctx, app.ListTenantsQuery{Status: app.StatusActive})
	if err != nil || len(active) != 2 {
		t.Fatalf("active filter = %d (%v), want 2", len(active), err)
	}
	susp, _ := svc.ListTenants(ctx, app.ListTenantsQuery{Status: app.StatusSuspended})
	if len(susp) != 1 || susp[0].ID() != "b" {
		t.Fatalf("suspended filter = %v", susp)
	}

	// Case-insensitive search over name.
	found, _ := svc.ListTenants(ctx, app.ListTenantsQuery{Search: "bravo"})
	if len(found) != 1 || found[0].ID() != "b" {
		t.Fatalf("search = %v", found)
	}
	none, _ := svc.ListTenants(ctx, app.ListTenantsQuery{Search: "zzz"})
	if len(none) != 0 {
		t.Fatalf("search miss = %v", none)
	}
}

func TestParseStatusFilter(t *testing.T) {
	t.Parallel()
	cases := map[string]app.StatusFilter{
		"active": app.StatusActive, "ACTIVE": app.StatusActive,
		"suspended": app.StatusSuspended, " suspended ": app.StatusSuspended,
		"": app.StatusAny, "garbage": app.StatusAny,
	}
	for in, want := range cases {
		if got := app.ParseStatusFilter(in); got != want {
			t.Errorf("ParseStatusFilter(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConsoleCreateAndGetTenant(t *testing.T) {
	t.Parallel()
	svc, _, _ := newConsole()
	ctx := context.Background()

	tn, err := svc.CreateTenant(ctx, "Acme")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tn.Name() != "Acme" || !tn.Active() {
		t.Fatalf("unexpected tenant %+v", tn)
	}
	got, err := svc.GetTenant(ctx, tn.ID())
	if err != nil || got.ID() != tn.ID() {
		t.Fatalf("get = %v, %v", got, err)
	}

	if _, err := svc.CreateTenant(ctx, "  "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("blank name err = %v, want validation", err)
	}
	if _, err := svc.GetTenant(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("get missing err = %v, want not found", err)
	}
}

func TestConsoleSuspendActivate(t *testing.T) {
	t.Parallel()
	svc, store, _ := newConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)

	susp, err := svc.SuspendTenant(ctx, "t1")
	if err != nil || susp.Active() {
		t.Fatalf("suspend = %v, %v", susp, err)
	}
	got, _ := svc.GetTenant(ctx, "t1")
	if got.Active() {
		t.Fatalf("suspend not persisted")
	}
	act, err := svc.ActivateTenant(ctx, "t1")
	if err != nil || !act.Active() {
		t.Fatalf("activate = %v, %v", act, err)
	}
	if _, err := svc.SuspendTenant(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("suspend missing err = %v", err)
	}
}

func TestConsoleSetBankCredential(t *testing.T) {
	t.Parallel()
	svc, store, creds := newConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)

	if err := svc.SetBankCredential(ctx, "t1", "client-1", "s3cr3t"); err != nil {
		t.Fatalf("set credential: %v", err)
	}
	got, err := creds.GetBankCredential(ctx, "t1")
	if err != nil || got.ClientID != "client-1" || got.Secret != "s3cr3t" {
		t.Fatalf("stored credential = %+v, %v", got, err)
	}

	if err := svc.SetBankCredential(ctx, "missing", "c", "s"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing tenant err = %v", err)
	}
	if err := svc.SetBankCredential(ctx, "t1", "c", ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty secret err = %v, want validation", err)
	}
}

func TestConsolePricing(t *testing.T) {
	t.Parallel()
	svc, store, _ := newConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)

	if _, err := svc.SetPrice(ctx, "t1", "POST /v1/charges", 250); err != nil {
		t.Fatalf("set price: %v", err)
	}
	// Idempotent upsert + a second endpoint.
	if _, err := svc.SetPrice(ctx, "t1", "POST /v1/charges", 250); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := svc.SetPrice(ctx, "t1", "GET /v1/charges", 10); err != nil {
		t.Fatalf("set price 2: %v", err)
	}
	prices, err := svc.ListPricing(ctx, "t1")
	if err != nil || len(prices) != 2 {
		t.Fatalf("list = %d (%v), want 2", len(prices), err)
	}
	// Ordered by endpoint: GET before POST.
	if prices[0].Endpoint() != "GET /v1/charges" || prices[1].PriceCents() != 250 {
		t.Fatalf("unexpected order/values %+v", prices)
	}

	if _, err := svc.SetPrice(ctx, "t1", "x", -1); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("negative price err = %v", err)
	}
	if _, err := svc.SetPrice(ctx, "missing", "x", 1); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing tenant err = %v", err)
	}
	if _, err := svc.ListPricing(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("list missing err = %v", err)
	}
}

func TestConsoleConsumption(t *testing.T) {
	t.Parallel()
	svc, store, _ := newConsole()
	ctx := context.Background()
	seedTenant(t, store, "t1", "Acme", true, 100)
	seedTenant(t, store, "t2", "Other", true, 100)

	appendLedger(t, store, "t1", "POST /v1/charges", 250, 1)
	appendLedger(t, store, "t1", "POST /v1/charges", 250, 2)
	appendLedger(t, store, "t1", "GET /v1/charges", 10, 3)
	appendLedger(t, store, "t2", "POST /v1/charges", 999, 4) // isolation: must not leak

	rep, err := svc.Consumption(ctx, "t1")
	if err != nil {
		t.Fatalf("consumption: %v", err)
	}
	if rep.TotalCalls != 3 || rep.TotalCents != 510 {
		t.Fatalf("totals = %d calls / %d cents, want 3/510", rep.TotalCalls, rep.TotalCents)
	}
	if len(rep.Lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(rep.Lines))
	}
	// Ordered by endpoint: GET first.
	if rep.Lines[0].Endpoint != "GET /v1/charges" || rep.Lines[0].Calls != 1 || rep.Lines[0].TotalCents != 10 {
		t.Fatalf("line0 = %+v", rep.Lines[0])
	}
	if rep.Lines[1].Calls != 2 || rep.Lines[1].TotalCents != 500 {
		t.Fatalf("line1 = %+v", rep.Lines[1])
	}

	// Empty tenant → zero report, no error.
	empty, err := svc.Consumption(ctx, "t2")
	if err != nil || empty.TotalCalls != 1 {
		t.Fatalf("t2 consumption = %+v, %v", empty, err)
	}
	if _, err := svc.Consumption(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing tenant err = %v", err)
	}
}

func appendLedger(t *testing.T, store *persistence.Store, tenantID, endpoint string, cents int64, idN int) {
	t.Helper()
	e, err := billing.NewLedgerEntry(
		"led-"+endpoint+"-"+itoaTest(idN), tenantID, endpoint, "ref", cents, time.Unix(int64(idN), 0).UTC())
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	if err := store.AppendLedgerEntry(context.Background(), e); err != nil {
		t.Fatalf("append ledger: %v", err)
	}
}

func itoaTest(n int) string {
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
