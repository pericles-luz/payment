package inmemory_test

import (
	"context"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
)

var memNow = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

func mkDelivery(t *testing.T, id, acct, tenantID, eventKey string) *outboundqueue.Delivery {
	t.Helper()
	d, err := outboundqueue.NewDelivery(id, acct, tenantID, eventKey, "tx", "payment.paid", outboundqueue.Detail{}, memNow)
	if err != nil {
		t.Fatalf("new delivery: %v", err)
	}
	return d
}

func mkDeadLetter(t *testing.T, id, tenantID, eventKey string) *outboundqueue.DeadLetter {
	t.Helper()
	dl, err := outboundqueue.NewDeadLetter(id, tenantID, eventKey, "tx", "payment.paid", outboundqueue.ReasonUnresolvable, memNow)
	if err != nil {
		t.Fatalf("new dead-letter: %v", err)
	}
	return dl
}

func TestInmemoryEnqueueAndPendingScoped(t *testing.T) {
	s := inmemory.NewOutboundDeliveryStore()
	ctx := context.Background()
	if err := s.EnqueueDelivery(ctx, mkDelivery(t, "d1", "acct-A", "ten-1", "ek-1")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	got, err := s.PendingDeliveries(ctx, "acct-A")
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(got) != 1 || got[0].ID() != "d1" {
		t.Fatalf("want d1, got %+v", got)
	}
	if other, _ := s.PendingDeliveries(ctx, "acct-B"); len(other) != 0 {
		t.Fatalf("cross-account leak: %d", len(other))
	}
}

func TestInmemoryEnqueueIdempotent(t *testing.T) {
	s := inmemory.NewOutboundDeliveryStore()
	ctx := context.Background()
	_ = s.EnqueueDelivery(ctx, mkDelivery(t, "d1", "acct-A", "ten-1", "ek-1"))
	_ = s.EnqueueDelivery(ctx, mkDelivery(t, "d2", "acct-A", "ten-1", "ek-1")) // same (acct,ek)
	got, _ := s.PendingDeliveries(ctx, "acct-A")
	if len(got) != 1 || got[0].ID() != "d1" {
		t.Fatalf("want single first-write-wins d1, got %+v", got)
	}
}

func TestInmemoryPerAccountDedup(t *testing.T) {
	s := inmemory.NewOutboundDeliveryStore()
	ctx := context.Background()
	_ = s.EnqueueDelivery(ctx, mkDelivery(t, "d1", "acct-A", "ten-1", "ek-1"))
	_ = s.EnqueueDelivery(ctx, mkDelivery(t, "d2", "acct-B", "ten-2", "ek-1")) // same ek, diff acct
	a, _ := s.PendingDeliveries(ctx, "acct-A")
	b, _ := s.PendingDeliveries(ctx, "acct-B")
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("want 1 each, got A=%d B=%d", len(a), len(b))
	}
}

func TestInmemoryDeadLetterIdempotent(t *testing.T) {
	s := inmemory.NewOutboundDeliveryStore()
	ctx := context.Background()
	_ = s.DeadLetter(ctx, mkDeadLetter(t, "dl1", "ten-1", "ek-1"))
	_ = s.DeadLetter(ctx, mkDeadLetter(t, "dl2", "ten-1", "ek-1")) // dup (tenant,ek)
	got, err := s.DeadLetters(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].ID() != "dl1" {
		t.Fatalf("want single dl1, got %+v", got)
	}
}
