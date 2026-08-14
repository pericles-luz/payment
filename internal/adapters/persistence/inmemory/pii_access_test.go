package inmemory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/access"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func piiEntry(t *testing.T, id, object string, at time.Time) access.Entry {
	t.Helper()
	e, err := access.NewEntry(access.NewEntryParams{
		ID: id, At: at, TenantID: "tnt-1", ClientID: "client-abc",
		SubjectRef: "hmac-sha256:" + id, Object: object, Action: access.ActionReadRec,
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	return e
}

func TestInmemRecordAndEntriesCopy(t *testing.T) {
	s := persistence.NewStore()
	ctx := context.Background()
	at := time.Unix(2000, 0).UTC()
	if err := s.RecordPIIAccess(ctx, piiEntry(t, "a", "rec:a", at)); err != nil {
		t.Fatalf("record: %v", err)
	}
	got := s.PIIAccessEntries()
	if len(got) != 1 || got[0].ID() != "a" {
		t.Fatalf("unexpected entries: %+v", got)
	}
	// Mutating the returned slice must not affect the store (append-only integrity).
	got[0] = access.Entry{}
	if again := s.PIIAccessEntries(); len(again) != 1 || again[0].ID() != "a" {
		t.Fatalf("returned slice was not a copy: %+v", again)
	}
}

// TestInmemAccessRollback proves the access append participates in WithinTx: an
// erroring tx rolls the entry back (matches the SQLite adapter's atomicity).
func TestInmemAccessRollback(t *testing.T) {
	s := persistence.NewStore()
	boom := errors.New("boom")
	err := s.WithinTx(context.Background(), func(r ports.Repository) error {
		if err := r.RecordPIIAccess(context.Background(), piiEntry(t, "x", "rec:x", time.Unix(1, 0).UTC())); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	if n := len(s.PIIAccessEntries()); n != 0 {
		t.Fatalf("entry survived rollback: %d", n)
	}
}

// TestInmemAccessCommitted proves a nil-return tx keeps the appended entry.
func TestInmemAccessCommitted(t *testing.T) {
	s := persistence.NewStore()
	err := s.WithinTx(context.Background(), func(r ports.Repository) error {
		return r.RecordPIIAccess(context.Background(), piiEntry(t, "y", "rec:y", time.Unix(1, 0).UTC()))
	})
	if err != nil {
		t.Fatalf("WithinTx: %v", err)
	}
	if n := len(s.PIIAccessEntries()); n != 1 {
		t.Fatalf("committed entry missing: %d", n)
	}
}

func TestInmemPurge(t *testing.T) {
	s := persistence.NewStore()
	ctx := context.Background()
	base := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	if err := s.RecordPIIAccess(ctx, piiEntry(t, "old", "rec:a", base.Add(-48*time.Hour))); err != nil {
		t.Fatalf("record old: %v", err)
	}
	if err := s.RecordPIIAccess(ctx, piiEntry(t, "fresh", "rec:b", base.Add(-1*time.Hour))); err != nil {
		t.Fatalf("record fresh: %v", err)
	}
	// Boundary: an entry exactly at the cutoff is KEPT (strictly-older is purged).
	if err := s.RecordPIIAccess(ctx, piiEntry(t, "edge", "rec:c", base.Add(-24*time.Hour))); err != nil {
		t.Fatalf("record edge: %v", err)
	}
	removed, err := s.PurgePIIAccessBefore(ctx, base.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	remaining := s.PIIAccessEntries()
	if len(remaining) != 2 {
		t.Fatalf("want 2 remaining, got %d", len(remaining))
	}
	for _, e := range remaining {
		if e.ID() == "old" {
			t.Fatalf("purged entry still present")
		}
	}
}
