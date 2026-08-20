package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/access"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

var errSentinel = errors.New("boom: sentinel to force rollback")

const (
	piiDoc     = "12345678901"
	piiNome    = "Fulano de Tal"
	piiHMACKey = "test-service-hmac-key-0123456789"
)

// piiRow mirrors one persisted pii_access_log row, read back via a direct query.
type piiRow struct {
	id, at, tenantID, clientID, operatorID, subjectRef, object, action string
	durationMs                                                         int64
}

func newPIIStore(t *testing.T) (*postgres.Store, string) {
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

func readPII(t *testing.T, dsn string) []piiRow {
	t.Helper()
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(context.Background(),
		`SELECT id, at, duration_ms, tenant_id, client_id, operator_id, subject_ref, object, action
		 FROM pii_access_log ORDER BY at ASC, id ASC`)
	if err != nil {
		t.Fatalf("query pii_access_log: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []piiRow
	for rows.Next() {
		var r piiRow
		if err := rows.Scan(&r.id, &r.at, &r.durationMs, &r.tenantID, &r.clientID,
			&r.operatorID, &r.subjectRef, &r.object, &r.action); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	return out
}

func piiTestEntry(t *testing.T, id, subjectRef, object string, at time.Time, dur time.Duration) access.Entry {
	t.Helper()
	e, err := access.NewEntry(access.NewEntryParams{
		ID: id, At: at, Duration: dur, TenantID: "tnt-1", ClientID: "client-abc",
		OperatorID: "op-9", SubjectRef: subjectRef, Object: object, Action: access.ActionReadRec,
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	return e
}

// TestRecordPIIAccessDurable records an access entry and reads it back on a FRESH
// connection to prove durability, and asserts the row carries no plaintext PII.
func TestRecordPIIAccessDurable(t *testing.T) {
	store, dsn := newPIIStore(t)
	pseudo, err := access.NewPseudonymizer([]byte(piiHMACKey))
	if err != nil {
		t.Fatalf("pseudo: %v", err)
	}
	at := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	ref := pseudo.Ref(piiDoc)
	if err := store.RecordPIIAccess(context.Background(),
		piiTestEntry(t, "acc-1", ref, "rec:idrec-1", at, 7*time.Millisecond)); err != nil {
		t.Fatalf("RecordPIIAccess: %v", err)
	}

	rows := readPII(t, dsn)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	r := rows[0]
	if r.id != "acc-1" || r.tenantID != "tnt-1" || r.clientID != "client-abc" ||
		r.operatorID != "op-9" || r.subjectRef != ref || r.object != "rec:idrec-1" ||
		r.action != string(access.ActionReadRec) || r.durationMs != 7 {
		t.Fatalf("row mismatch: %+v", r)
	}
	// Minimisation: no column holds the plaintext document or name.
	for _, f := range []string{r.id, r.at, r.tenantID, r.clientID, r.operatorID, r.subjectRef, r.object, r.action} {
		if f == piiDoc || f == piiNome {
			t.Fatalf("row leaked plaintext PII: %q", f)
		}
	}
}

// TestRecordPIIAccessAtomicWithinTx proves the append participates in the unit of
// work: a tx that errors after recording access rolls the access row back (Complete
// Mediation — no unlogged read, and no logged-but-rolled-back read either).
func TestRecordPIIAccessAtomicWithinTx(t *testing.T) {
	store, dsn := newPIIStore(t)
	at := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	wantErr := errSentinel
	err := store.WithinTx(context.Background(), func(r ports.Repository) error {
		if err := r.RecordPIIAccess(context.Background(), piiTestEntry(t, "acc-rollback", "hmac-sha256:x", "rec:z", at, 0)); err != nil {
			return err
		}
		return wantErr
	})
	if err != wantErr {
		t.Fatalf("WithinTx err = %v, want sentinel", err)
	}
	if rows := readPII(t, dsn); len(rows) != 0 {
		t.Fatalf("access row survived a rolled-back tx: %+v", rows)
	}
}

// TestPurgePIIAccessBefore expires entries older than the cutoff and keeps newer
// ones (append-safe retention).
func TestPurgePIIAccessBefore(t *testing.T) {
	store, dsn := newPIIStore(t)
	base := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	if err := store.RecordPIIAccess(ctx, piiTestEntry(t, "old", "hmac-sha256:a", "rec:a", base.Add(-48*time.Hour), 0)); err != nil {
		t.Fatalf("record old: %v", err)
	}
	if err := store.RecordPIIAccess(ctx, piiTestEntry(t, "fresh", "hmac-sha256:b", "rec:b", base.Add(-1*time.Hour), 0)); err != nil {
		t.Fatalf("record fresh: %v", err)
	}
	removed, err := store.PurgePIIAccessBefore(ctx, base.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	rows := readPII(t, dsn)
	if len(rows) != 1 || rows[0].id != "fresh" {
		t.Fatalf("unexpected rows after purge: %+v", rows)
	}
}
