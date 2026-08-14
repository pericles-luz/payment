package inmemory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

// TestInMemoryAccountRoundTrip exercises the account plane of the in-memory store
// (two-level tenancy, SIN-69157): save/find/list with newest-first ordering, and
// upsert-on-id (deactivate is retry-safe). It matches the SQLite adapter behaviour.
func TestInMemoryAccountRoundTrip(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()

	a, _ := account.New("a1", "Verz", time.Unix(1, 0).UTC())
	if err := s.SaveAccount(ctx, a); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.FindAccountByID(ctx, "a1")
	if err != nil || got.Name() != "Verz" || !got.Active() {
		t.Fatalf("find = %+v, %v", got, err)
	}
	if _, err := s.FindAccountByID(ctx, "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing err = %v", err)
	}

	// Upsert: deactivate then re-save keeps a single row, now inactive.
	a.Deactivate()
	if err := s.SaveAccount(ctx, a); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = s.FindAccountByID(ctx, "a1")
	if got.Active() {
		t.Fatal("expected inactive after upsert")
	}
}

func TestInMemoryListAccounts_NewestFirst(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	_ = s.SaveAccount(ctx, account.Rehydrate("a", "A", true, time.Unix(100, 0).UTC()))
	_ = s.SaveAccount(ctx, account.Rehydrate("b", "B", true, time.Unix(300, 0).UTC()))
	_ = s.SaveAccount(ctx, account.Rehydrate("c", "C", true, time.Unix(200, 0).UTC()))

	got, err := s.ListAccounts(ctx)
	if err != nil || len(got) != 3 {
		t.Fatalf("list = %d (%v), want 3", len(got), err)
	}
	want := []string{"b", "c", "a"} // newest-first, id desc tie-break
	for i, id := range want {
		if got[i].ID() != id {
			t.Fatalf("order[%d] = %s, want %s", i, got[i].ID(), id)
		}
	}

	// Empty store lists nothing without error.
	empty, err := inmemory.NewStore().ListAccounts(ctx)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty list = %d, %v", len(empty), err)
	}
}
