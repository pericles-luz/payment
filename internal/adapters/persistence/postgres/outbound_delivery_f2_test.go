package postgres_test

import (
	"context"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
)

// ClaimPendingDeliveries returns pending rows ACROSS Contas, oldest first, bounded by
// limit — the batch F2's processor forwards. DeleteDelivery removes a settled row.
func TestClaimAndDeletePendingDeliveries(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	store := postgres.NewOutboundDeliveryStore(db)

	// Two Contas, three events.
	for _, d := range []struct{ id, acct, ek string }{
		{"d1", "acct-A", "ek-1"},
		{"d2", "acct-B", "ek-2"},
		{"d3", "acct-A", "ek-3"},
	} {
		if err := store.EnqueueDelivery(ctx, newDelivery(t, d.id, d.acct, "ten-1", d.ek, "tx")); err != nil {
			t.Fatalf("enqueue %s: %v", d.id, err)
		}
	}

	// Cross-account claim: all three, bounded by a generous limit.
	got, err := store.ClaimPendingDeliveries(ctx, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 pending across Contas, got %d", len(got))
	}

	// Limit is honored.
	limited, err := store.ClaimPendingDeliveries(ctx, 2)
	if err != nil {
		t.Fatalf("claim limited: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("limit 2 returned %d", len(limited))
	}

	// A non-positive limit yields nothing.
	if none, _ := store.ClaimPendingDeliveries(ctx, 0); len(none) != 0 {
		t.Fatalf("limit 0 returned %d", len(none))
	}

	// Delete d2 (acct-B) — it leaves the outbox; the others remain.
	if err := store.DeleteDelivery(ctx, "d2"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	after, _ := store.ClaimPendingDeliveries(ctx, 10)
	if len(after) != 2 {
		t.Fatalf("want 2 after delete, got %d", len(after))
	}
	if left, _ := store.PendingDeliveries(ctx, "acct-B"); len(left) != 0 {
		t.Fatalf("acct-B should be empty after delete, got %d", len(left))
	}

	// Delete is idempotent (absent id is a no-op).
	if err := store.DeleteDelivery(ctx, "nope"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}
