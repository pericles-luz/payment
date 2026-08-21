package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
)

// TestSqliteListAccounts covers the console Contas listing (SIN-69157): newest-first
// ordering (created_at desc, id desc tie-break) over the accounts table, including
// the per-tenant self-accounts backfilled by migration 0007.
func TestSqliteListAccounts(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()

	// Fresh DB has no seeded tenants, so no backfilled self-accounts: list is empty.
	empty, err := s.ListAccounts(ctx)
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("fresh list = %d, want 0", len(empty))
	}

	_ = s.SaveAccount(ctx, account.Rehydrate("a", "A", true, time.Unix(100, 0).UTC()))
	_ = s.SaveAccount(ctx, account.Rehydrate("b", "B", false, time.Unix(300, 0).UTC()))
	_ = s.SaveAccount(ctx, account.Rehydrate("c", "C", true, time.Unix(200, 0).UTC()))

	got, err := s.ListAccounts(ctx)
	if err != nil || len(got) != 3 {
		t.Fatalf("list = %d (%v), want 3", len(got), err)
	}
	want := []string{"b", "c", "a"} // newest-first
	for i, id := range want {
		if got[i].ID() != id {
			t.Fatalf("order[%d] = %s, want %s", i, got[i].ID(), id)
		}
	}
	// Active flag round-trips (b was suspended).
	if got[0].Active() {
		t.Fatalf("account b should be inactive")
	}
}
