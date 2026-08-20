package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// The suite needs a live PostgreSQL. Point PAYMENT_TEST_DB_DSN at one; without it
// every test here skips, so `go test ./...` stays green on a machine that has no
// server. CI sets it from a postgres:16 service container.
//
//	docker run -d -p 55432:5432 -e POSTGRES_PASSWORD=test postgres:16
//	export PAYMENT_TEST_DB_DSN='postgres://postgres:test@127.0.0.1:55432/postgres?sslmode=disable'
const dsnEnv = "PAYMENT_TEST_DB_DSN"

var dbSeq atomic.Int64

// testDSN provisions an EMPTY database and returns its DSN, dropping it when the
// test ends.
//
// Empty, not migrated, on purpose: it reproduces what filepath.Join(t.TempDir(),
// "x.db") gives the sqlite suite. Each test then migrates it exactly as it does
// there, and a test that reopens the same DSN to prove durability sees the same
// rows — so the ported tests read the same as their originals.
func testDSN(t *testing.T) string {
	t.Helper()
	admin := os.Getenv(dsnEnv)
	if admin == "" {
		t.Skipf("%s not set — skipping the PostgreSQL adapter suite", dsnEnv)
	}
	name := fmt.Sprintf("payment_test_%d_%d", os.Getpid(), dbSeq.Add(1))

	adminDB, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	defer func() { _ = adminDB.Close() }()
	if _, err := adminDB.ExecContext(context.Background(), `CREATE DATABASE `+quoteIdent(name)); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	t.Cleanup(func() {
		db, err := sql.Open("pgx", admin)
		if err != nil {
			return
		}
		defer func() { _ = db.Close() }()
		// FORCE disconnects anything the test left behind; without it a leaked
		// handle turns cleanup into a failure that masks the real one.
		_, _ = db.ExecContext(context.Background(), `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`)
	})
	return replaceDBName(admin, name)
}

// quoteIdent renders a SQL identifier. CREATE/DROP DATABASE take no parameters, so
// the name has to be inlined; it is built from a pid and a counter, never input.
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// replaceDBName swaps the database in a libpq URL for name, keeping every other
// connection parameter (host, credentials, sslmode) as given.
func replaceDBName(dsn, name string) string {
	q := ""
	if i := strings.Index(dsn, "?"); i >= 0 {
		q, dsn = dsn[i:], dsn[:i]
	}
	if i := strings.LastIndex(dsn, "/"); i >= 0 {
		dsn = dsn[:i+1] + name
	}
	return dsn + q
}
