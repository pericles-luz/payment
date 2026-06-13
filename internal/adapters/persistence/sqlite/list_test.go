package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
)

func seedTenants(t *testing.T, s *sqlite.Store, ids ...string) {
	t.Helper()
	for i, id := range ids {
		// created_at increasing with index so the last id is newest.
		tn := tenant.Rehydrate(id, "name-"+id, true, time.Unix(int64(100+i*100), 0).UTC())
		if err := s.SaveTenant(context.Background(), tn); err != nil {
			t.Fatalf("seed tenant %s: %v", id, err)
		}
	}
}

func TestSQLiteListTenants(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	seedTenants(t, s, "a", "b", "c") // c newest

	got, err := s.ListTenants(ctx)
	if err != nil || len(got) != 3 {
		t.Fatalf("list = %d (%v), want 3", len(got), err)
	}
	want := []string{"c", "b", "a"}
	for i, id := range want {
		if got[i].ID() != id {
			t.Fatalf("order[%d] = %s, want %s", i, got[i].ID(), id)
		}
	}

	empty, err := newStore(t).ListTenants(ctx)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty = %d (%v)", len(empty), err)
	}
}

func TestSQLiteListEndpointPrices(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	seedTenants(t, s, "t1", "t2")
	for _, p := range []struct {
		tenant, endpoint string
		cents            int64
	}{
		{"t1", "POST /v1/charges", 250},
		{"t1", "GET /v1/charges", 10},
		{"t2", "POST /v1/charges", 999},
	} {
		ep, _ := billing.NewEndpointPricing(p.tenant, p.endpoint, p.cents)
		if err := s.UpsertEndpointPrice(ctx, ep); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	got, err := s.ListEndpointPrices(ctx, "t1")
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %d (%v), want 2 (isolation)", len(got), err)
	}
	if got[0].Endpoint() != "GET /v1/charges" || got[1].PriceCents() != 250 {
		t.Fatalf("unexpected %+v", got)
	}
	none, _ := s.ListEndpointPrices(ctx, "t2")
	if len(none) != 1 {
		t.Fatalf("t2 = %d, want 1", len(none))
	}
}

func TestSQLiteListLedgerEntries(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	seedTenants(t, s, "t1", "t2")
	add := func(id, tenantID, endpoint string, at int64, cents int64) {
		e, err := billing.NewLedgerEntry(id, tenantID, endpoint, "ref", cents, time.Unix(at, 0).UTC())
		if err != nil {
			t.Fatalf("new ledger: %v", err)
		}
		if err := s.AppendLedgerEntry(ctx, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	add("e1", "t1", "POST", 100, 250)
	add("e2", "t1", "GET", 300, 10)
	add("e3", "t2", "POST", 200, 999)

	got, err := s.ListLedgerEntries(ctx, "t1")
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %d (%v), want 2 (isolation)", len(got), err)
	}
	if got[0].ID() != "e2" || got[1].PriceCents() != 250 {
		t.Fatalf("unexpected order/values %+v", got)
	}
}
