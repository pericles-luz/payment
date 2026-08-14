package inmemory_test

import (
	"context"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

func TestInMemoryListTenants(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	_ = s.SaveTenant(ctx, tenant.Rehydrate("a", "A", true, time.Unix(100, 0).UTC()))
	_ = s.SaveTenant(ctx, tenant.Rehydrate("b", "B", true, time.Unix(300, 0).UTC()))
	_ = s.SaveTenant(ctx, tenant.Rehydrate("c", "C", true, time.Unix(200, 0).UTC()))

	got, err := s.ListTenants(ctx)
	if err != nil || len(got) != 3 {
		t.Fatalf("list = %d (%v), want 3", len(got), err)
	}
	want := []string{"b", "c", "a"} // newest-first
	for i, id := range want {
		if got[i].ID() != id {
			t.Fatalf("order[%d] = %s, want %s", i, got[i].ID(), id)
		}
	}

	empty, _ := inmemory.NewStore().ListTenants(ctx)
	if len(empty) != 0 {
		t.Fatalf("empty store list = %d", len(empty))
	}
}

func TestInMemoryListEndpointPrices(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	for _, p := range []struct {
		tenant, endpoint string
		cents            int64
	}{
		{"t1", "POST /v1/charges", 250},
		{"t1", "GET /v1/charges", 10},
		{"t2", "POST /v1/charges", 999},
	} {
		ep, _ := billing.NewEndpointPricing(p.tenant, p.endpoint, p.cents)
		_ = s.UpsertEndpointPrice(ctx, ep)
	}
	got, err := s.ListEndpointPrices(ctx, "t1")
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %d (%v), want 2 (isolation)", len(got), err)
	}
	if got[0].Endpoint() != "GET /v1/charges" {
		t.Fatalf("order = %v, want GET first", got)
	}
}

func TestInMemoryListLedgerEntries(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	add := func(id, tenantID, endpoint string, at int64) {
		e, _ := billing.NewLedgerEntry(id, tenantID, endpoint, "ref", 100, time.Unix(at, 0).UTC())
		_ = s.AppendLedgerEntry(ctx, e)
	}
	add("e1", "t1", "POST", 100)
	add("e2", "t1", "GET", 300)
	add("e3", "t2", "POST", 200) // other tenant: excluded

	got, err := s.ListLedgerEntries(ctx, "t1")
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %d (%v), want 2 (isolation)", len(got), err)
	}
	if got[0].ID() != "e2" { // newest-first
		t.Fatalf("order = %s, want e2 first", got[0].ID())
	}
}

// TestInMemoryListLedgerEntriesByAccount checks the account rollup read (SIN-69127):
// an account's entries are returned across all its tenants, newest-first, with no
// cross-account leakage — parity with the SQLite adapter.
func TestInMemoryListLedgerEntriesByAccount(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	add := func(id, accountID, tenantID, endpoint string, at int64) {
		e, _ := billing.NewLedgerEntry(id, tenantID, endpoint, "ref", 100, time.Unix(at, 0).UTC(),
			billing.WithAccount(accountID))
		_ = s.AppendLedgerEntry(ctx, e)
	}
	add("e1", "acct-A", "t1", "POST", 100)
	add("e2", "acct-A", "t2", "GET", 300)  // newest, different tenant, same account
	add("e3", "acct-B", "t3", "POST", 200) // other account: excluded

	got, err := s.ListLedgerEntriesByAccount(ctx, "acct-A")
	if err != nil || len(got) != 2 {
		t.Fatalf("by account = %d (%v), want 2 (across t1+t2, no acct-B)", len(got), err)
	}
	if got[0].ID() != "e2" { // newest-first
		t.Fatalf("order = %s, want e2 first", got[0].ID())
	}
	for _, e := range got {
		if e.AccountID() != "acct-A" {
			t.Fatalf("entry %s account = %q, want acct-A", e.ID(), e.AccountID())
		}
	}
}
