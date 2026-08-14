package inmemory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func auditEntry(t *testing.T, id string) audit.Entry {
	t.Helper()
	e, err := audit.NewEntry(id, "op-1", audit.ActionCreateTenant, "ten-1", time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("new entry: %v", err)
	}
	return e
}

// TestAuditAppendAndCopy mirrors the SQLite adapter: entries append in order and
// AuditEntries returns a copy callers cannot use to mutate the trail.
func TestAuditAppendAndCopy(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		if err := s.Append(ctx, auditEntry(t, id)); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	got := s.AuditEntries()
	if len(got) != 3 || got[0].ID() != "a" || got[2].ID() != "c" {
		t.Fatalf("append order: %+v", got)
	}
	// Mutating the returned slice must not affect the trail.
	got[0] = auditEntry(t, "tampered")
	if s.AuditEntries()[0].ID() != "a" {
		t.Fatal("AuditEntries must return a copy")
	}
}

// TestAuditRollsBackWithTx proves the audit append is part of the unit-of-work
// snapshot: a failing transaction discards the appended entry.
func TestAuditRollsBackWithTx(t *testing.T) {
	t.Parallel()
	s := inmemory.NewStore()
	ctx := context.Background()
	errBoom := errors.New("boom")

	err := s.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.Append(ctx, auditEntry(t, "rollback-me")); err != nil {
			return err
		}
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("want errBoom, got %v", err)
	}
	if got := s.AuditEntries(); len(got) != 0 {
		t.Fatalf("rolled-back append must not persist, got %d", len(got))
	}

	// A committing tx keeps the entry.
	if err := s.WithinTx(ctx, func(r ports.Repository) error {
		return r.Append(ctx, auditEntry(t, "keep-me"))
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := s.AuditEntries(); len(got) != 1 || got[0].ID() != "keep-me" {
		t.Fatalf("committed append must persist, got %+v", got)
	}
}
