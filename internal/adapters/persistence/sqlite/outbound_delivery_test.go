package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
)

var delNow = time.Unix(1700000000, 0).UTC()

func newDelivery(t *testing.T, id, acct, tenantID, eventKey, txID string) *outboundqueue.Delivery {
	t.Helper()
	d, err := outboundqueue.NewDelivery(id, acct, tenantID, eventKey, txID, "payment.paid", outboundqueue.Detail{}, delNow)
	if err != nil {
		t.Fatalf("new delivery: %v", err)
	}
	return d
}

func newDeadLetter(t *testing.T, id, tenantID, eventKey, txID string) *outboundqueue.DeadLetter {
	t.Helper()
	dl, err := outboundqueue.NewDeadLetter(id, tenantID, eventKey, txID, "payment.paid", outboundqueue.ReasonUnresolvable, delNow)
	if err != nil {
		t.Fatalf("new dead-letter: %v", err)
	}
	return dl
}

// A queued delivery survives a process restart (durable) and reads back account-scoped.
func TestOutboundDeliveryRoundTripSurvivesRestart(t *testing.T) {
	t.Parallel()
	dsn, db := openVaultDB(t)
	ctx := context.Background()

	if err := sqlite.NewOutboundDeliveryStore(db).EnqueueDelivery(ctx, newDelivery(t, "d1", "acct-verz", "ten-1", "ek-1", "tx-1")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	_ = db.Close()

	db2, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	got, err := sqlite.NewOutboundDeliveryStore(db2).PendingDeliveries(ctx, "acct-verz")
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 delivery after restart, got %d", len(got))
	}
	d := got[0]
	if d.ID() != "d1" || d.AccountID() != "acct-verz" || d.TenantID() != "ten-1" ||
		d.EventKey() != "ek-1" || d.TxID() != "tx-1" || d.EventType() != "payment.paid" ||
		d.Status() != outboundqueue.StatusPending {
		t.Fatalf("round-trip mismatch: %+v", d)
	}
}

// Idempotency/dedup: enqueuing the SAME (account, event_key) twice keeps one row.
func TestOutboundDeliveryIdempotentEnqueue(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	s := sqlite.NewOutboundDeliveryStore(db)

	if err := s.EnqueueDelivery(ctx, newDelivery(t, "d1", "acct-verz", "ten-1", "ek-1", "tx-1")); err != nil {
		t.Fatalf("enqueue 1: %v", err)
	}
	// Same (account, event_key), different id — must be a no-op, not a duplicate/PK error.
	if err := s.EnqueueDelivery(ctx, newDelivery(t, "d2", "acct-verz", "ten-1", "ek-1", "tx-1")); err != nil {
		t.Fatalf("enqueue dup: %v", err)
	}
	got, _ := s.PendingDeliveries(ctx, "acct-verz")
	if len(got) != 1 {
		t.Fatalf("want 1 after dup, got %d", len(got))
	}
	if got[0].ID() != "d1" {
		t.Fatalf("first-write-wins expected d1, got %s", got[0].ID())
	}
}

// The SAME event_key under a DIFFERENT account is a distinct delivery (isolation): dedup
// is per (account, event_key), not global.
func TestOutboundDeliveryPerAccountDedup(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	s := sqlite.NewOutboundDeliveryStore(db)

	if err := s.EnqueueDelivery(ctx, newDelivery(t, "d1", "acct-A", "ten-1", "ek-1", "tx-1")); err != nil {
		t.Fatalf("enqueue A: %v", err)
	}
	if err := s.EnqueueDelivery(ctx, newDelivery(t, "d2", "acct-B", "ten-2", "ek-1", "tx-1")); err != nil {
		t.Fatalf("enqueue B: %v", err)
	}
	a, _ := s.PendingDeliveries(ctx, "acct-A")
	b, _ := s.PendingDeliveries(ctx, "acct-B")
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("want 1 each, got A=%d B=%d", len(a), len(b))
	}
	// A never sees B's row.
	if a[0].AccountID() != "acct-A" {
		t.Fatalf("cross-account leak: %+v", a[0])
	}
}

// Dead-letter persists, reads back, and is idempotent on (tenant, event_key).
func TestOutboundDeadLetterRoundTripAndIdempotent(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	s := sqlite.NewOutboundDeliveryStore(db)

	if err := s.DeadLetter(ctx, newDeadLetter(t, "dl1", "ten-1", "ek-1", "tx-1")); err != nil {
		t.Fatalf("deadletter: %v", err)
	}
	// Duplicate (tenant, event_key), different id ⇒ no-op.
	if err := s.DeadLetter(ctx, newDeadLetter(t, "dl2", "ten-1", "ek-1", "tx-1")); err != nil {
		t.Fatalf("deadletter dup: %v", err)
	}
	got, err := s.DeadLetters(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 dead-letter, got %d", len(got))
	}
	dl := got[0]
	if dl.ID() != "dl1" || dl.TenantID() != "ten-1" || dl.EventKey() != "ek-1" ||
		dl.TxID() != "tx-1" || dl.EventType() != "payment.paid" || dl.Reason() != outboundqueue.ReasonUnresolvable {
		t.Fatalf("dead-letter round-trip mismatch: %+v", dl)
	}
}

// A closed DB surfaces an error on every operation (fail-closed, no silent drop).
func TestOutboundDeliveryClosedDBErrors(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	s := sqlite.NewOutboundDeliveryStore(db)
	_ = db.Close()
	ctx := context.Background()

	if err := s.EnqueueDelivery(ctx, newDelivery(t, "d1", "acct-A", "ten-1", "ek-1", "tx-1")); err == nil {
		t.Fatalf("expected enqueue error on closed db")
	}
	if err := s.DeadLetter(ctx, newDeadLetter(t, "dl1", "ten-1", "ek-1", "tx-1")); err == nil {
		t.Fatalf("expected deadletter error on closed db")
	}
	if _, err := s.PendingDeliveries(ctx, "acct-A"); err == nil {
		t.Fatalf("expected pending error on closed db")
	}
	if _, err := s.DeadLetters(ctx); err == nil {
		t.Fatalf("expected deadletters error on closed db")
	}
}

// PendingDeliveries returns only the requested account's rows.
func TestPendingDeliveriesAccountScoped(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	s := sqlite.NewOutboundDeliveryStore(db)
	_ = s.EnqueueDelivery(ctx, newDelivery(t, "d1", "acct-A", "ten-1", "ek-1", "tx-1"))

	got, err := s.PendingDeliveries(ctx, "acct-B")
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 for acct-B, got %d", len(got))
	}
}
