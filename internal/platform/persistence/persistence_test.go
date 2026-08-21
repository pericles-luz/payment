package persistence_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/platform/persistence"
)

// With no DSN the SQLite file is used, and Open leaves it migrated and usable.
func TestOpenWithoutDSNSelectsSQLite(t *testing.T) {
	t.Parallel()
	db, err := persistence.Open(context.Background(), "", filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if db.Engine != persistence.EngineSQLite {
		t.Fatalf("engine = %q, want %q", db.Engine, persistence.EngineSQLite)
	}
	// Migrations ran: the ledger exists and the schema is there.
	var n int
	if err := db.SQL.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("ledger: %v", err)
	}
	if n == 0 {
		t.Fatal("no migrations applied")
	}
	if db.Store() == nil {
		t.Fatal("nil store")
	}
}

// A DSN wins over a path, and it is not a preference — it is the guard that keeps a
// deployment pointed at the cluster from silently falling back to an empty local
// file when PAYMENT_DB_PATH happens to be set too. Here the DSN is deliberately
// unreachable, so "it tried PostgreSQL" is exactly what the error proves; falling
// back to SQLite would have returned nil.
func TestOpenPrefersDSNOverPath(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "must-not-be-used.db")
	_, err := persistence.Open(context.Background(),
		"postgres://nobody@127.0.0.1:1/nothing?sslmode=disable&connect_timeout=1", path)
	if err == nil {
		t.Fatal("want an error from the unreachable DSN, got nil — it fell back to SQLite")
	}
	if _, statErr := filepath.Abs(path); statErr != nil {
		t.Fatalf("abs: %v", statErr)
	}
}
