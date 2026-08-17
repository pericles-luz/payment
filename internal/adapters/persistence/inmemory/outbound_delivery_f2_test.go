package inmemory_test

import (
	"context"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
)

var memF2Now = time.Date(2026, 8, 17, 16, 0, 0, 0, time.UTC)

func memDelivery(t *testing.T, id, acct, ek string) *outboundqueue.Delivery {
	t.Helper()
	d, err := outboundqueue.NewDelivery(id, acct, "ten-1", ek, "tx", "payment.paid", memF2Now)
	if err != nil {
		t.Fatalf("new delivery: %v", err)
	}
	return d
}

func TestInMemoryClaimAndDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmemory.NewOutboundDeliveryStore()
	for _, d := range []struct{ id, acct, ek string }{
		{"d1", "acct-A", "ek-1"},
		{"d2", "acct-B", "ek-2"},
		{"d3", "acct-A", "ek-3"},
	} {
		if err := s.EnqueueDelivery(ctx, memDelivery(t, d.id, d.acct, d.ek)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	got, _ := s.ClaimPendingDeliveries(ctx, 10)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	if got[0].ID() != "d1" {
		t.Fatalf("expected insertion order oldest-first, got %s first", got[0].ID())
	}
	if lim, _ := s.ClaimPendingDeliveries(ctx, 1); len(lim) != 1 {
		t.Fatalf("limit 1 returned %d", len(lim))
	}
	if none, _ := s.ClaimPendingDeliveries(ctx, 0); len(none) != 0 {
		t.Fatalf("limit 0 returned %d", len(none))
	}

	if err := s.DeleteDelivery(ctx, "d2"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	after, _ := s.ClaimPendingDeliveries(ctx, 10)
	if len(after) != 2 {
		t.Fatalf("want 2 after delete, got %d", len(after))
	}

	// Deleting clears the dedup key so a legitimate re-attribution of the SAME event can
	// re-enqueue (mirrors the sqlite row being gone).
	if err := s.EnqueueDelivery(ctx, memDelivery(t, "d2b", "acct-B", "ek-2")); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	if b, _ := s.PendingDeliveries(ctx, "acct-B"); len(b) != 1 {
		t.Fatalf("acct-B should have 1 after re-enqueue, got %d", len(b))
	}

	// Idempotent delete of an absent id.
	if err := s.DeleteDelivery(ctx, "nope"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}
