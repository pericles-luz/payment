package postgres_test

import (
	"context"
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// upToFS returns the migrations up to and including the given prefix. Rolling a
// migration back only makes sense with the later ones already rolled back: 0011
// creates account_keys REFERENCES accounts, so on Postgres 0007.down cannot drop
// accounts while it stands. SQLite let that pass — it accepts a REFERENCES to a
// table that is not there and does not block the DROP — which is why the sqlite
// suite got away with applying all 18 first.
func upToFS(t *testing.T, through string) fs.FS {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	m := fstest.MapFS{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") || name[:5] > through[:5] {
			continue
		}
		b, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		m[name] = &fstest.MapFile{Data: b}
	}
	return m
}

// legacyFS returns a migrations filesystem containing every *.up.sql BEFORE 0007,
// so a test can materialise the pre-0007 (flat, one-level) schema, seed legacy
// data, and then apply 0007 to observe the self-account backfill on rows that
// already existed.
func legacyFS(t *testing.T) fs.FS {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	m := fstest.MapFS{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") || name >= "0007_" {
			continue
		}
		b, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		m[name] = &fstest.MapFile{Data: b}
	}
	return m
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func queryInt(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return n
}

// Every legacy tenant that existed before 0007 gets EXACTLY ONE self-account, 1:1,
// and the ledger/audit rows are backfilled with that self-account.
func TestMigration0007BackfillSelfAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := postgres.Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Pre-0007 flat schema.
	if err := postgres.Migrate(ctx, db, legacyFS(t)); err != nil {
		t.Fatalf("legacy migrate: %v", err)
	}

	// Seed two legacy tenants (no account_id column yet) + dependent rows.
	mustExec(t, db, `INSERT INTO tenants (id, name, active, created_at) VALUES ('t1','Acme',1,'2026-01-01T00:00:00Z')`)
	mustExec(t, db, `INSERT INTO tenants (id, name, active, created_at) VALUES ('t2','Beta',0,'2026-01-02T00:00:00Z')`)
	mustExec(t, db, `INSERT INTO billing_ledger (id, tenant_id, endpoint, price_cents, reference, at) VALUES ('l1','t1','/pix',10,'p1','2026-01-03T00:00:00Z')`)
	mustExec(t, db, `INSERT INTO billing_ledger (id, tenant_id, endpoint, price_cents, reference, at) VALUES ('l2','t2','/boleto',20,'p2','2026-01-04T00:00:00Z')`)

	// Apply 0007.
	mustExec(t, db, readMigration(t, "0007_two_level_tenancy.up.sql"))

	// Exactly one account per tenant, 1:1.
	if nAcc, nTen := queryInt(t, db, `SELECT COUNT(*) FROM accounts`), queryInt(t, db, `SELECT COUNT(*) FROM tenants`); nAcc != nTen || nAcc != 2 {
		t.Fatalf("want 2 accounts == 2 tenants, got accounts=%d tenants=%d", nAcc, nTen)
	}
	// Every tenant points at its derived self-account, which exists and mirrors the tenant.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM tenants WHERE account_id IS NULL`); n != 0 {
		t.Fatalf("want no NULL account_id after backfill, got %d", n)
	}
	if n := queryInt(t, db,
		`SELECT COUNT(*) FROM tenants t JOIN accounts a ON t.account_id = a.id
		 WHERE a.id = 'acct-' || t.id AND a.name = t.name AND a.active = t.active AND a.created_at = t.created_at`); n != 2 {
		t.Fatalf("want 2 tenants matched 1:1 to a mirrored self-account, got %d", n)
	}
	// Ledger backfilled from the tenant's self-account. (audit_log.account_id is
	// deferred to F2, so it is intentionally not asserted here.)
	if got := queryInt(t, db, `SELECT COUNT(*) FROM billing_ledger WHERE account_id = 'acct-' || tenant_id`); got != 2 {
		t.Fatalf("want 2 ledger rows backfilled, got %d", got)
	}

	// The (account_id, at) rollup index exists.
	if got := queryInt(t, db, `SELECT COUNT(*) FROM pg_indexes WHERE schemaname='public' AND indexname='ix_ledger_account_at'`); got != 1 {
		t.Fatalf("want ix_ledger_account_at index, got %d", got)
	}
}

// 0007 is reversible: applying up then down restores the flat schema (accounts
// table + all account_id columns gone), and up re-applies cleanly afterwards.
func TestMigration0007Reversible(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := postgres.Open(testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Schema through 0007 — see upToFS for why later migrations must stay out.
	if err := postgres.Migrate(ctx, db, upToFS(t, "0007_")); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// A tenant inserted post-migration owns a self-account only if we assign it; to
	// prove the down path we just need the columns/table present, which Migrate did.
	if got := queryInt(t, db, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='accounts'`); got != 1 {
		t.Fatalf("accounts table should exist after up, got %d", got)
	}

	// Down.
	mustExec(t, db, readMigration(t, "0007_two_level_tenancy.down.sql"))
	if got := queryInt(t, db, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='accounts'`); got != 0 {
		t.Fatalf("accounts table should be dropped after down, got %d", got)
	}
	if got := queryInt(t, db, `SELECT COUNT(*) FROM pg_indexes WHERE schemaname='public' AND indexname='ix_ledger_account_at'`); got != 0 {
		t.Fatalf("ledger index should be dropped after down, got %d", got)
	}
	for _, tbl := range []string{"tenants", "billing_ledger"} {
		if columnExists(t, db, tbl, "account_id") {
			t.Fatalf("%s.account_id should be dropped after down", tbl)
		}
	}

	// Re-apply up: reversible round-trip must succeed.
	mustExec(t, db, readMigration(t, "0007_two_level_tenancy.up.sql"))
	if got := queryInt(t, db, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='accounts'`); got != 1 {
		t.Fatalf("accounts table should exist after re-apply, got %d", got)
	}
}

func columnExists(t *testing.T, db *sql.DB, table, col string) bool {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1`, table)
	if err != nil {
		t.Fatalf("columns of %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == col {
			return true
		}
	}
	return false
}
