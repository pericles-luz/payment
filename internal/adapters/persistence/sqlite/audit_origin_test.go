package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
)

// originEpoch is the fixed timestamp used by the origin persistence tests.
func originEpoch() time.Time { return time.Unix(1700000000, 0).UTC() }

// queryOrigin reads the origin column of the audit_log row with the given id via a
// fresh connection to the DSN (reading the append-only trail directly in a test is
// fine; application code only ever appends).
func queryOrigin(t *testing.T, dsn, id string) string {
	t.Helper()
	db, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	var origin string
	if err := db.QueryRowContext(context.Background(),
		`SELECT origin FROM audit_log WHERE id = ?`, id).Scan(&origin); err != nil {
		t.Fatalf("query origin for %q: %v", id, err)
	}
	return origin
}

// TestAuditOriginPersisted asserts the origin column round-trips: an admin
// credential entry persists origin='admin' (the default surface) and a self-serve
// entry persists origin='self-serve' — so the durable trail distinguishes the two
// write surfaces (SIN-69196 R1 / migration 0010).
func TestAuditOriginPersisted(t *testing.T) {
	t.Parallel()
	store, dsn := newAuditStore(t)
	ctx := context.Background()

	adminE, err := audit.NewCredentialSetEntry("adm-1", "op-1", "ten-1", "c6", originEpoch())
	if err != nil {
		t.Fatalf("admin entry: %v", err)
	}
	selfE, err := audit.NewSelfServeCredentialSetEntry("self-1", "op-1", "ten-1", "c6", originEpoch())
	if err != nil {
		t.Fatalf("self-serve entry: %v", err)
	}
	if err := store.Append(ctx, adminE); err != nil {
		t.Fatalf("append admin: %v", err)
	}
	if err := store.Append(ctx, selfE); err != nil {
		t.Fatalf("append self-serve: %v", err)
	}

	if got := queryOrigin(t, dsn, "adm-1"); got != audit.OriginAdmin {
		t.Fatalf("admin entry origin = %q, want %q", got, audit.OriginAdmin)
	}
	if got := queryOrigin(t, dsn, "self-1"); got != audit.OriginSelfServe {
		t.Fatalf("self-serve entry origin = %q, want %q", got, audit.OriginSelfServe)
	}
}

// TestAuditOriginDefaultsAdminForLegacyWrite proves the migration DEFAULT is what
// makes the change backward-compatible: a row inserted WITHOUT the origin column
// (simulating a pre-0010 writer against a post-0010 schema) reads back as 'admin'.
func TestAuditOriginDefaultsAdminForLegacyWrite(t *testing.T) {
	t.Parallel()
	_, dsn := newAuditStore(t)
	db, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert omitting origin — the column DEFAULT must fill it.
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO audit_log (id, operator_id, action, tenant_id, at) VALUES (?, ?, ?, ?, ?)`,
		"legacy-1", "op-1", string(audit.ActionCreateTenant), "ten-1", originEpoch().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	if got := queryOrigin(t, dsn, "legacy-1"); got != audit.OriginAdmin {
		t.Fatalf("legacy row origin = %q, want %q (migration DEFAULT)", got, audit.OriginAdmin)
	}
}
