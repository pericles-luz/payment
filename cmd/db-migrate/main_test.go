package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	sqlitemigrations "github.com/ia-dev-sindireceita/payment/migrations"
	pgmigrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// The end-to-end check: a SQLite database shaped like the deployed one — sealed
// blobs, an FK chain, and timestamps written the way the SQLite adapter wrote them
// — copied into a real PostgreSQL and inspected on the far side.
//
// Set PAYMENT_TEST_DB_DSN to run it; without a server it skips.
func TestCopyEndToEnd(t *testing.T) {
	admin := os.Getenv("PAYMENT_TEST_DB_DSN")
	if admin == "" {
		t.Skip("PAYMENT_TEST_DB_DSN not set — skipping the ETL end-to-end test")
	}
	ctx := context.Background()

	src := buildSource(t)
	dst := freshTarget(t, admin)
	if err := postgres.Migrate(ctx, dst, pgmigrations.FS); err != nil {
		t.Fatalf("migrate target: %v", err)
	}
	if err := copyAll(ctx, src, dst, false); err != nil {
		t.Fatalf("copy: %v", err)
	}

	// The FK chain survived: the child row is there, pointing at its parent.
	var tenantAccount string
	if err := dst.QueryRowContext(ctx, `SELECT account_id FROM tenants WHERE id = 'ten-1'`).Scan(&tenantAccount); err != nil {
		t.Fatalf("read tenant: %v", err)
	}
	if tenantAccount != "acct-1" {
		t.Fatalf("tenant owner = %q, want acct-1", tenantAccount)
	}

	// Sealed bytes are byte-for-byte. Anything else and the KEK stops opening them.
	var sealed []byte
	if err := dst.QueryRowContext(ctx,
		`SELECT secret_sealed FROM bank_credentials WHERE tenant_id = 'ten-1'`).Scan(&sealed); err != nil {
		t.Fatalf("read sealed: %v", err)
	}
	if !bytes.Equal(sealed, sealedFixture) {
		t.Fatalf("sealed bytes changed: got %x, want %x", sealed, sealedFixture)
	}

	// Timestamps arrive at a fixed width, whatever width they had. Both source rows
	// were written the way RFC3339Nano writes them: one trimmed, one not.
	rows, err := dst.QueryContext(ctx, `SELECT id, at FROM billing_ledger ORDER BY id`)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]string{}
	for rows.Next() {
		var id, at string
		if err := rows.Scan(&id, &at); err != nil {
			t.Fatalf("scan ledger: %v", err)
		}
		got[id] = at
	}
	want := map[string]string{
		"led-1": "2026-01-01T00:00:01.000000000Z", // was "…:01Z"
		"led-2": "2026-01-01T00:00:01.500000000Z", // was "…:01.5Z"
	}
	for id, w := range want {
		if got[id] != w {
			t.Fatalf("ledger %s at = %q, want %q", id, got[id], w)
		}
	}
	// And now they sort the way time runs, which they did not before.
	if !(got["led-1"] < got["led-2"]) {
		t.Fatalf("lexical order still disagrees with time order: %q !< %q", got["led-1"], got["led-2"])
	}
}

// A second pass must be a no-op on rows already carried over — that is what makes
// the cutover's delta run safe to repeat.
func TestCopyIsRepeatable(t *testing.T) {
	admin := os.Getenv("PAYMENT_TEST_DB_DSN")
	if admin == "" {
		t.Skip("PAYMENT_TEST_DB_DSN not set — skipping the ETL end-to-end test")
	}
	ctx := context.Background()
	src := buildSource(t)
	dst := freshTarget(t, admin)
	if err := postgres.Migrate(ctx, dst, pgmigrations.FS); err != nil {
		t.Fatalf("migrate target: %v", err)
	}
	if err := copyAll(ctx, src, dst, false); err != nil {
		t.Fatalf("first copy: %v", err)
	}
	if err := copyAll(ctx, src, dst, false); err != nil {
		t.Fatalf("second copy: %v", err)
	}
	var n int
	if err := dst.QueryRowContext(ctx, `SELECT COUNT(*) FROM billing_ledger`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("ledger has %d rows after two passes, want 2", n)
	}
}

// A dry run must leave the target untouched.
func TestDryRunKeepsNothing(t *testing.T) {
	admin := os.Getenv("PAYMENT_TEST_DB_DSN")
	if admin == "" {
		t.Skip("PAYMENT_TEST_DB_DSN not set — skipping the ETL end-to-end test")
	}
	ctx := context.Background()
	src := buildSource(t)
	dst := freshTarget(t, admin)
	if err := postgres.Migrate(ctx, dst, pgmigrations.FS); err != nil {
		t.Fatalf("migrate target: %v", err)
	}
	if err := copyAll(ctx, src, dst, true); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	var n int
	if err := dst.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("dry run left %d tenants behind", n)
	}
}

var sealedFixture = []byte{0x00, 0x01, 0xff, 0xfe, 0x7f, 0x80, 0x00, 0x2a}

// buildSource writes a SQLite database with the shape that matters: an account, a
// tenant that references it, a sealed credential, and two ledger rows whose
// timestamps straddle the fraction boundary — written EXACTLY as the SQLite adapter
// writes them (RFC3339Nano, trailing zeros trimmed).
func buildSource(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := sqlite.Migrate(context.Background(), db, sqlitemigrations.FS); err != nil {
		t.Fatalf("migrate source: %v", err)
	}
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	base := time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	exec(`INSERT INTO accounts (id, name, active, created_at) VALUES (?, ?, 1, ?)`,
		"acct-1", "Reseller", base.Format(time.RFC3339Nano))
	exec(`INSERT INTO tenants (id, name, active, created_at, account_id) VALUES (?, ?, 1, ?, ?)`,
		"ten-1", "Cliente", base.Format(time.RFC3339Nano), "acct-1")
	// One trimmed fraction, one not — the pair that ordered wrong as text.
	exec(`INSERT INTO billing_ledger (id, tenant_id, endpoint, price_cents, reference, at, account_id)
	      VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"led-1", "ten-1", "/v1/charges", 100, "r1", base.Format(time.RFC3339Nano), "acct-1")
	exec(`INSERT INTO billing_ledger (id, tenant_id, endpoint, price_cents, reference, at, account_id)
	      VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"led-2", "ten-1", "/v1/charges", 100, "r2",
		base.Add(500*time.Millisecond).Format(time.RFC3339Nano), "acct-1")
	exec(`INSERT INTO bank_credentials (tenant_id, bank_id, client_id, secret_sealed, creditor_key_sealed, updated_at)
	      VALUES (?, ?, ?, ?, NULL, ?)`,
		"ten-1", "c6", "client-abc", sealedFixture, base.Format(time.RFC3339Nano))
	exec(`INSERT INTO processed_events (tenant_id, event_key, processed_at) VALUES (?, ?, ?)`,
		"ten-1", "tx1|pix|CONCLUIDA", base.Format(time.RFC3339Nano))
	return db
}

// freshTarget creates an empty scratch database and returns a handle to it.
func freshTarget(t *testing.T, admin string) *sql.DB {
	t.Helper()
	name := "etl_test_" + time.Now().UTC().Format("150405.000000000")
	name = filepath.Base(name)
	for i := range name {
		if name[i] == '.' {
			name = name[:i] + "_" + name[i+1:]
		}
	}
	adminDB, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	defer func() { _ = adminDB.Close() }()
	if _, err := adminDB.ExecContext(context.Background(), `CREATE DATABASE "`+name+`"`); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		db, err := sql.Open("pgx", admin)
		if err != nil {
			return
		}
		defer func() { _ = db.Close() }()
		_, _ = db.ExecContext(context.Background(), `DROP DATABASE IF EXISTS "`+name+`" WITH (FORCE)`)
	})
	dsn := admin
	q := ""
	if i := lastIndexByte(dsn, '?'); i >= 0 {
		q, dsn = dsn[i:], dsn[:i]
	}
	if i := lastIndexByte(dsn, '/'); i >= 0 {
		dsn = dsn[:i+1] + name
	}
	db, err := postgres.Open(dsn + q)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
