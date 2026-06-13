package inmemory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	auditlog "github.com/ia-dev-sindireceita/payment/internal/adapters/audit/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
)

func mustEntry(t *testing.T, id, tenant string) audit.Entry {
	t.Helper()
	e, err := audit.NewEntry(id, "op-1", audit.ActionCreateTenant, tenant, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("new entry: %v", err)
	}
	return e
}

func TestAppendAndEntriesInOrder(t *testing.T) {
	t.Parallel()
	log := auditlog.NewLog()
	if log.Len() != 0 {
		t.Fatalf("new log not empty: %d", log.Len())
	}
	for i, id := range []string{"a", "b", "c"} {
		if err := log.Append(context.Background(), mustEntry(t, id, "ten")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	got := log.Entries()
	if len(got) != 3 || got[0].ID() != "a" || got[1].ID() != "b" || got[2].ID() != "c" {
		t.Fatalf("entries out of order: %+v", got)
	}
	if log.Len() != 3 {
		t.Fatalf("len: %d", log.Len())
	}
}

// TestEntriesReturnsCopy ensures callers cannot mutate the underlying trail
// through the returned slice (append-only integrity).
func TestEntriesReturnsCopy(t *testing.T) {
	t.Parallel()
	log := auditlog.NewLog()
	_ = log.Append(context.Background(), mustEntry(t, "a", "ten"))
	got := log.Entries()
	got[0] = mustEntry(t, "tampered", "ten")
	if log.Entries()[0].ID() != "a" {
		t.Fatal("mutating the returned slice altered the log")
	}
}

func TestAppendConcurrent(t *testing.T) {
	t.Parallel()
	log := auditlog.NewLog()
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_ = log.Append(context.Background(), mustEntry(t, "id", "ten"))
		}(i)
	}
	wg.Wait()
	if log.Len() != n {
		t.Fatalf("want %d entries, got %d", n, log.Len())
	}
}
