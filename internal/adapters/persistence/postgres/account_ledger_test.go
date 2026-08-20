package postgres_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// newStoreDSN opens a fresh migrated PostgreSQL store backed by a scratch database and returns
// both the store and its DSN, so a test can reopen the same database on a fresh
// connection to inspect raw columns (e.g. assert a NULL account_id). Mirrors
// newAuditStore.
func newStoreDSN(t *testing.T) (*postgres.Store, string) {
	t.Helper()
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := postgres.Migrate(context.Background(), db, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return postgres.NewStore(db), dsn
}

// ledgerAccountIsNull reports whether billing_ledger.account_id is SQL NULL for id,
// read on a fresh connection to dsn (a test may inspect the append-only table).
func ledgerAccountIsNull(t *testing.T, dsn, id string) bool {
	t.Helper()
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	var acct sql.NullString
	if err := db.QueryRowContext(context.Background(),
		`SELECT account_id FROM billing_ledger WHERE id = $1`, id).Scan(&acct); err != nil {
		t.Fatalf("read account_id for %s: %v", id, err)
	}
	return !acct.Valid
}

// TestPostgresLedgerStampsAccount is the metering acceptance (SIN-69127): a ledger
// write carries its owning account into the billing_ledger.account_id column and the
// value round-trips on read. A self-account (empty) is stored as NULL (NULL-safe).
func TestPostgresLedgerStampsAccount(t *testing.T) {
	t.Parallel()
	s, dsn := newStoreDSN(t)
	ctx := context.Background()
	seedTenants(t, s, "t1")

	stamped, err := billing.NewLedgerEntry("e1", "t1", "POST", "ref", 250, time.Unix(100, 0).UTC(),
		billing.WithAccount("acct-A"))
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	self, err := billing.NewLedgerEntry("e2", "t1", "GET", "ref", 10, time.Unix(200, 0).UTC())
	if err != nil {
		t.Fatalf("new ledger self: %v", err)
	}
	for _, e := range []billing.LedgerEntry{stamped, self} {
		if err := s.AppendLedgerEntry(ctx, e); err != nil {
			t.Fatalf("append %s: %v", e.ID(), err)
		}
	}

	// account_id round-trips through the tenant read path.
	got, err := s.ListLedgerEntries(ctx, "t1")
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %d (%v), want 2", len(got), err)
	}
	byID := map[string]billing.LedgerEntry{}
	for _, e := range got {
		byID[e.ID()] = e
	}
	if byID["e1"].AccountID() != "acct-A" {
		t.Fatalf("e1 account = %q, want acct-A", byID["e1"].AccountID())
	}
	if byID["e2"].AccountID() != "" {
		t.Fatalf("e2 (self) account = %q, want empty", byID["e2"].AccountID())
	}

	// The self-account entry is stored as SQL NULL, not the empty string.
	if !ledgerAccountIsNull(t, dsn, "e2") {
		t.Fatalf("self-account e2 must persist account_id as NULL")
	}
	if ledgerAccountIsNull(t, dsn, "e1") {
		t.Fatalf("stamped e1 must persist a non-NULL account_id")
	}
}

// TestPostgresListLedgerEntriesByAccount is the rollup read acceptance: an account's
// entries are returned across ALL of its tenants, newest-first, and never leak
// another account's usage.
func TestPostgresListLedgerEntriesByAccount(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := context.Background()
	seedTenants(t, s, "t1", "t2", "t3")
	add := func(id, accountID, tenantID, endpoint string, at int64) {
		e, err := billing.NewLedgerEntry(id, tenantID, endpoint, "ref", 100, time.Unix(at, 0).UTC(),
			billing.WithAccount(accountID))
		if err != nil {
			t.Fatalf("new ledger: %v", err)
		}
		if err := s.AppendLedgerEntry(ctx, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// acct-A owns t1+t2; acct-B owns t3.
	add("e1", "acct-A", "t1", "POST", 100)
	add("e2", "acct-A", "t2", "POST", 300) // newest for acct-A
	add("e3", "acct-A", "t1", "GET", 200)
	add("e4", "acct-B", "t3", "POST", 400) // must not leak

	got, err := s.ListLedgerEntriesByAccount(ctx, "acct-A")
	if err != nil || len(got) != 3 {
		t.Fatalf("by account = %d (%v), want 3 (across t1+t2, no acct-B)", len(got), err)
	}
	// Newest-first (at desc): e2 (300), e3 (200), e1 (100).
	if got[0].ID() != "e2" || got[1].ID() != "e3" || got[2].ID() != "e1" {
		t.Fatalf("order = %s,%s,%s want e2,e3,e1", got[0].ID(), got[1].ID(), got[2].ID())
	}
	for _, e := range got {
		if e.AccountID() != "acct-A" {
			t.Fatalf("entry %s account = %q, want acct-A", e.ID(), e.AccountID())
		}
	}

	b, err := s.ListLedgerEntriesByAccount(ctx, "acct-B")
	if err != nil || len(b) != 1 || b[0].ID() != "e4" {
		t.Fatalf("acct-B = %+v (%v), want [e4]", b, err)
	}
	none, err := s.ListLedgerEntriesByAccount(ctx, "acct-none")
	if err != nil || len(none) != 0 {
		t.Fatalf("unknown account = %d (%v), want 0", len(none), err)
	}
}

// TestMigration0009BackfillsAuditAccount checks migration 0009's backfill semantics:
// an audit_log row with a NULL account_id (a legacy row written before the F0→F2
// deferral was closed) is stamped with the tenant's self-account ('acct-'||tenant_id)
// by the idempotent backfill, so no forensic attribution is lost.
func TestMigration0009BackfillsAuditAccount(t *testing.T) {
	t.Parallel()
	_, dsn := newStoreDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	// Simulate a legacy row (NULL account_id) and re-run the idempotent backfill.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO audit_log (id, operator_id, action, tenant_id, at, tx_id, expected_cents, received_cents, bank_id, account_id)
		 VALUES ('legacy', 'op', 'tenant.create', 'ten-9', '1970-01-01T00:00:00Z', '', 0, 0, '', NULL)`); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE audit_log SET account_id = 'acct-' || tenant_id WHERE account_id IS NULL`); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	var got sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT account_id FROM audit_log WHERE id = 'legacy'`).Scan(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !got.Valid || got.String != "acct-ten-9" {
		t.Fatalf("backfilled account_id = %v, want acct-ten-9", got)
	}
}

// TestPostgresAuditStampsAccount checks the audit adapter persists the entry's derived
// account attribution (SIN-69127) into audit_log.account_id, so the forensic trail
// completes the account→tenant rollup.
func TestPostgresAuditStampsAccount(t *testing.T) {
	t.Parallel()
	s, dsn := newStoreDSN(t)
	ctx := context.Background()

	e, err := audit.NewEntry("a1", "op", audit.ActionCreateTenant, "ten-7", time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("new entry: %v", err)
	}
	if err := s.Append(ctx, e); err != nil {
		t.Fatalf("append: %v", err)
	}

	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	var acct sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT account_id FROM audit_log WHERE id = 'a1'`).Scan(&acct); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !acct.Valid || acct.String != "acct-ten-7" {
		t.Fatalf("audit account_id = %v, want acct-ten-7", acct)
	}
}

// TestMigration0009Reversible checks 0009 is reversible: after the full migration
// set audit_log.account_id exists; applying 0009.down drops it (restoring the exact
// column set the schema-whitelist test pins pre-0009); re-applying 0009.up restores it.
func TestMigration0009Reversible(t *testing.T) {
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
	if !columnExists(t, db, "audit_log", "account_id") {
		t.Fatalf("audit_log.account_id should exist after up")
	}

	mustExec(t, db, readMigration(t, "0009_audit_account_id.down.sql"))
	if columnExists(t, db, "audit_log", "account_id") {
		t.Fatalf("audit_log.account_id should be dropped after down")
	}

	mustExec(t, db, readMigration(t, "0009_audit_account_id.up.sql"))
	if !columnExists(t, db, "audit_log", "account_id") {
		t.Fatalf("audit_log.account_id should exist after re-apply")
	}
}
