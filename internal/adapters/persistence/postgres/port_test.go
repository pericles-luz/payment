package postgres_test

import (
	"context"
	"fmt"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// These cover what the move off SQLite could break QUIETLY — no behaviour visibly
// changes, so nothing else in the suite would notice.

// The ledger recognises every shipped migration, applies each once, and a second
// Migrate on the same database is a no-op. This is what makes Migrate safe to call
// on every boot, and what lets a database carried over from SQLite keep its
// history: the file names are identical in both migration sets.
func TestMigrationLedgerAppliesEachFileOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if err := postgres.Migrate(ctx, db, migrations.FS); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	var first int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&first); err != nil {
		t.Fatalf("count ledger: %v", err)
	}
	if first == 0 {
		t.Fatal("ledger is empty after migrating")
	}

	// Re-running must not re-apply anything. Additive migrations (ALTER TABLE ADD
	// COLUMN) are not idempotent, so a runner without the ledger would fail here.
	if err := postgres.Migrate(ctx, db, migrations.FS); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var second int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&second); err != nil {
		t.Fatalf("re-count ledger: %v", err)
	}
	if second != first {
		t.Fatalf("ledger grew on re-run: %d -> %d", first, second)
	}

	// Every *.up.sql shipped is recorded — a file silently skipped would leave the
	// schema short of what the code expects.
	names, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	want := 0
	for _, n := range names {
		if !n.IsDir() && len(n.Name()) > 7 && n.Name()[len(n.Name())-7:] == ".up.sql" {
			want++
		}
	}
	if first != want {
		t.Fatalf("ledger has %d entries, want %d (one per .up.sql)", first, want)
	}
}

// A migration file is one transaction: a failure leaves neither the schema
// half-changed nor the file marked applied. The batch is sent through the simple
// query protocol, which is the part that differs from the sqlite runner, so it is
// worth proving the BEGIN/COMMIT wrapping actually holds.
func TestMigrationFailureIsAtomic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := postgres.Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// A file that creates a table and then fails. Neither may survive.
	bad := fstest.MapFS{"0001_bad.up.sql": &fstest.MapFile{
		Data: []byte("CREATE TABLE should_not_survive (id TEXT PRIMARY KEY);\nSELECT 1/0;\n"),
	}}
	if err := postgres.Migrate(ctx, db, bad); err == nil {
		t.Fatal("expected the failing migration to error")
	}
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='should_not_survive'`).Scan(&n); err != nil {
		t.Fatalf("check table: %v", err)
	}
	if n != 0 {
		t.Fatal("the failing migration left its table behind — the batch was not atomic")
	}
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations WHERE name = '0001_bad.up.sql'`).Scan(&n); err != nil {
		t.Fatalf("check ledger: %v", err)
	}
	if n != 0 {
		t.Fatal("the failing migration was recorded as applied")
	}
}

// Timestamps are TEXT and every ORDER BY on them is lexical, so the stored width
// has to be constant. Under time.RFC3339Nano — what the sqlite adapter uses — a
// whole second is written "…:00Z" and a fraction of it "…:00.5Z"; at index 19 'Z'
// (0x5A) sorts after '.' (0x2E), which puts the whole second AFTER the fraction it
// precedes. This walks a ledger through exactly that boundary.
func TestLedgerOrderingAcrossFractionBoundary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := postgres.Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := postgres.Migrate(ctx, db, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := postgres.NewStore(db)
	seedTenant(t, s, "t-ord")

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Chronological order. The middle two straddle the boundary: a whole second and
	// half a second past it.
	times := []time.Time{
		base,
		base.Add(500 * time.Millisecond),
		base.Add(1 * time.Second),
		base.Add(1500 * time.Millisecond),
	}
	for i, at := range times {
		e, err := billing.NewLedgerEntry(fmt.Sprintf("l%02d", i), "t-ord", "/v1/charges", "ref", 100, at)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if err := s.AppendLedgerEntry(ctx, e); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	got, err := s.ListLedgerEntries(ctx, "t-ord")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != len(times) {
		t.Fatalf("got %d entries, want %d", len(got), len(times))
	}
	// ListLedgerEntries orders newest-first, so the list must be the reverse of the
	// chronological order we wrote.
	for i, e := range got {
		want := times[len(times)-1-i]
		if !e.At().Equal(want) {
			t.Fatalf("position %d: got %s, want %s — lexical order disagrees with time order",
				i, e.At().Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
		}
	}
}

// mapFS is a minimal fs.FS over an in-memory file set, enough for Migrate: it only
// ever needs ReadDir and ReadFile, which fstest.MapFS already provides.
