package postgres_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// auditRow mirrors one persisted audit_log row, read back via a direct query
// (reading the append-only trail directly in a test is fine; application code
// only ever appends).
type auditRow struct {
	id, operatorID, action, tenantID, at, txID, bankID string
	expected, received                                 int64
}

// newAuditStore opens a fresh migrated PostgreSQL database backed by a scratch DATABASE (not
// :memory:) so a "restart" — closing and reopening the same DSN — exercises real
// durability. It returns the store and the DSN.
func newAuditStore(t *testing.T) (*postgres.Store, string) {
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

// readAudit reopens the DSN on a fresh connection and reads the whole trail,
// ordered by posting time then id for determinism.
func readAudit(t *testing.T, dsn string) []auditRow {
	t.Helper()
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(context.Background(),
		`SELECT id, operator_id, action, tenant_id, at, tx_id, expected_cents, received_cents, bank_id
		 FROM audit_log ORDER BY at ASC, id ASC`)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.id, &r.operatorID, &r.action, &r.tenantID, &r.at, &r.txID, &r.expected, &r.received, &r.bankID); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	return out
}

func mustEntry(t *testing.T, id, operator string, action audit.Action, tenant string, at time.Time) audit.Entry {
	t.Helper()
	e, err := audit.NewEntry(id, operator, action, tenant, at)
	if err != nil {
		t.Fatalf("new entry: %v", err)
	}
	return e
}

// TestAuditAppendDurableAcrossRestart is the core acceptance: an appended entry
// survives a process restart (close + reopen the same DSN).
func TestAuditAppendDurableAcrossRestart(t *testing.T) {
	t.Parallel()
	store, dsn := newAuditStore(t)
	ctx := context.Background()
	at := time.Unix(100, 0).UTC()

	if err := store.Append(ctx, mustEntry(t, "a1", "op-7", audit.ActionCreateTenant, "ten-1", at)); err != nil {
		t.Fatalf("append: %v", err)
	}

	// Reopen the same database file: the entry must still be there.
	got := readAudit(t, dsn)
	if len(got) != 1 {
		t.Fatalf("want 1 row after restart, got %d", len(got))
	}
	r := got[0]
	if r.id != "a1" || r.operatorID != "op-7" || r.action != string(audit.ActionCreateTenant) || r.tenantID != "ten-1" {
		t.Fatalf("row mismatch after restart: %+v", r)
	}
	// Fixed-width fraction, deliberately NOT time.RFC3339Nano: these columns are
	// TEXT and get compared lexically by every ORDER BY, so a trimmed fraction would
	// sort a whole second after a fraction of that same second.
	if r.at != at.Format("2006-01-02T15:04:05.000000000Z07:00") {
		t.Fatalf("timestamp not preserved: %q", r.at)
	}
}

// TestAuditPreservesAttribution checks the pseudonymous operator id is preserved,
// including the empty operator (non-attributed internal caller) and the reserved
// system actor on a settlement-mismatch event, with its cents and txid.
func TestAuditPreservesAttribution(t *testing.T) {
	t.Parallel()
	store, dsn := newAuditStore(t)
	ctx := context.Background()

	human := mustEntry(t, "h1", "operator-42", audit.ActionSetBankCredential, "ten-1", time.Unix(1, 0).UTC())
	internal := mustEntry(t, "i1", "", audit.ActionCreateTenant, "ten-1", time.Unix(2, 0).UTC())
	mismatch, err := audit.NewSettlementMismatchEntry("m1", "system:c6-webhook", "ten-1", "tx-9", 100, 60, time.Unix(3, 0).UTC())
	if err != nil {
		t.Fatalf("mismatch entry: %v", err)
	}
	// A credential.set entry carries the non-secret bank slug (SIN-66044): the
	// durable trail must record WHICH bank's credential was (re)written.
	cred, err := audit.NewCredentialSetEntry("c1", "operator-42", "ten-1", "c6", time.Unix(4, 0).UTC())
	if err != nil {
		t.Fatalf("credential entry: %v", err)
	}
	for _, e := range []audit.Entry{human, internal, mismatch, cred} {
		if err := store.Append(ctx, e); err != nil {
			t.Fatalf("append %s: %v", e.ID(), err)
		}
	}

	byID := map[string]auditRow{}
	for _, r := range readAudit(t, dsn) {
		byID[r.id] = r
	}
	if got := byID["h1"].operatorID; got != "operator-42" {
		t.Fatalf("human operator id = %q", got)
	}
	if got := byID["i1"].operatorID; got != "" {
		t.Fatalf("internal operator id should be empty, got %q", got)
	}
	m := byID["m1"]
	if m.operatorID != "system:c6-webhook" || m.txID != "tx-9" || m.expected != 100 || m.received != 60 {
		t.Fatalf("system-actor mismatch row not preserved: %+v", m)
	}
	if m.action != string(audit.ActionSettlementAmountMismatch) {
		t.Fatalf("mismatch action = %q", m.action)
	}
	// bank_id round-trips for credential.set; legacy/non-credential entries store ''.
	if got := byID["c1"].bankID; got != "c6" {
		t.Fatalf("credential.set bank_id should round-trip, got %q", got)
	}
	if got := byID["c1"].action; got != string(audit.ActionSetBankCredential) {
		t.Fatalf("credential.set action = %q", got)
	}
	for _, id := range []string{"h1", "i1", "m1"} {
		if got := byID[id].bankID; got != "" {
			t.Fatalf("non-credential entry %s bank_id should be empty, got %q", id, got)
		}
	}
}

// TestAuditAppendAtomicWithTriggeringTx is the atomicity acceptance: an append
// performed through the unit of work rolls back together with the triggering
// operation when the transaction fails — nothing persists.
func TestAuditAppendAtomicWithTriggeringTx(t *testing.T) {
	t.Parallel()
	store, dsn := newAuditStore(t)
	ctx := context.Background()
	errBoom := errors.New("boom after append")

	// Append inside the tx, then force the tx to fail: the row must NOT persist.
	err := store.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.Append(ctx, mustEntry(t, "rollback-me", "op-1", audit.ActionCreateTenant, "ten-1", time.Unix(1, 0).UTC())); err != nil {
			return err
		}
		return errBoom // post-append failure in the same tx
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("want errBoom, got %v", err)
	}
	if got := readAudit(t, dsn); len(got) != 0 {
		t.Fatalf("rolled-back append must not persist, got %d rows", len(got))
	}

	// Control: a committing tx persists the append atomically with its work.
	if err := store.WithinTx(ctx, func(r ports.Repository) error {
		return r.Append(ctx, mustEntry(t, "keep-me", "op-1", audit.ActionCreateTenant, "ten-1", time.Unix(2, 0).UTC()))
	}); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
	got := readAudit(t, dsn)
	if len(got) != 1 || got[0].id != "keep-me" {
		t.Fatalf("committed append must persist exactly once, got %+v", got)
	}
}

// TestAuditOrderPreserved checks entries are read back in posting order.
func TestAuditOrderPreserved(t *testing.T) {
	t.Parallel()
	store, dsn := newAuditStore(t)
	ctx := context.Background()
	ids := []string{"e1", "e2", "e3"}
	for i, id := range ids {
		at := time.Unix(int64(10+i), 0).UTC()
		if err := store.Append(ctx, mustEntry(t, id, "op", audit.ActionCreateTenant, "ten-1", at)); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	got := readAudit(t, dsn)
	if len(got) != 3 {
		t.Fatalf("want 3 rows, got %d", len(got))
	}
	for i, id := range ids {
		if got[i].id != id {
			t.Fatalf("order not preserved at %d: got %q want %q", i, got[i].id, id)
		}
	}
}

// TestAuditSchemaCarriesNoSecretColumn asserts the audit_log schema records only
// who/what/tenant/when (+ txid and cents) — and crucially NO secret/credential
// column, so a secret can never be persisted to the trail (threat C1/C4).
func TestAuditSchemaCarriesNoSecretColumn(t *testing.T) {
	t.Parallel()
	_, dsn := newAuditStore(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows, err := db.QueryContext(context.Background(), `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'audit_log'`)
	if err != nil {
		t.Fatalf("query columns: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		cols = append(cols, name)
	}
	sort.Strings(cols)
	// bank_id (non-secret bank slug, SIN-66044) is expected; it carries no secret.
	// account_id ('acct-<tenant_id>' attribution, SIN-69127) is likewise non-secret —
	// added by migration 0009 with CTO authorization to update this allow-list.
	// origin (closed label 'admin'|'self-serve', SIN-69196 / migration 0010) is also
	// non-secret — it names the write SURFACE, never a credential; added with CTO
	// authorization to update this allow-list by one line (same as 0009).
	want := []string{"account_id", "action", "at", "bank_id", "expected_cents", "id", "operator_id", "origin", "received_cents", "tenant_id", "tx_id"}
	if len(cols) != len(want) {
		t.Fatalf("audit_log columns = %v, want %v", cols, want)
	}
	for i := range want {
		if cols[i] != want[i] {
			t.Fatalf("audit_log columns = %v, want %v", cols, want)
		}
	}
	// Defense-in-depth: no column name hints at carrying a secret.
	for _, c := range cols {
		switch c {
		case "secret", "password", "client_secret", "credential", "token":
			t.Fatalf("audit_log must not have a secret-bearing column: %q", c)
		}
	}
}
