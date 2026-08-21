package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// newWebhookRefStore opens a fresh migrated DB, seeds the given tenants (FK parents),
// and returns the raw handle (for at-rest assertions) plus the ref store.
func newWebhookRefStore(t *testing.T, clock *akClock, tenantIDs ...string) (*sql.DB, *postgres.WebhookRefStore) {
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
	repo := postgres.NewStore(db)
	for _, id := range tenantIDs {
		tn, err := tenant.New(id, "Tenant "+id, time.Unix(0, 0).UTC())
		if err != nil {
			t.Fatalf("new tenant: %v", err)
		}
		if err := repo.SaveTenant(context.Background(), tn); err != nil {
			t.Fatalf("save tenant: %v", err)
		}
	}
	return db, postgres.NewWebhookRefStore(db, clock)
}

func sumOf(t *testing.T, ref string) []byte {
	t.Helper()
	s := webhookref.Sum(ref)
	return s[:]
}

// TestPostgresWebhookRefPutLookup is the happy path: a minted ref persists and resolves
// to its tenant after being written durably.
func TestPostgresWebhookRefPutLookup(t *testing.T) {
	t.Parallel()
	_, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-1")
	ctx := context.Background()

	ref, err := webhookref.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := s.PutWebhookRef(ctx, sumOf(t, ref), "tenant-1"); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok, err := s.LookupWebhookRef(ctx, sumOf(t, ref))
	if err != nil || !ok || got != "tenant-1" {
		t.Fatalf("lookup = (%q, %v, %v), want (tenant-1, true, nil)", got, ok, err)
	}
}

// TestPostgresWebhookRefHashAtRest proves the plaintext ref is NEVER written: the stored
// ref_sha256 equals hex(sha256(ref)) and no row contains the plaintext.
func TestPostgresWebhookRefHashAtRest(t *testing.T) {
	t.Parallel()
	db, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-1")
	ctx := context.Background()

	ref, _ := webhookref.Generate()
	if err := s.PutWebhookRef(ctx, sumOf(t, ref), "tenant-1"); err != nil {
		t.Fatalf("put: %v", err)
	}
	var hit int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webhook_tenant_refs WHERE ref_sha256 = $1`, ref).Scan(&hit); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if hit != 0 {
		t.Fatal("plaintext ref must never appear in ref_sha256")
	}
	// The stored value is the hex sha256, distinct from the plaintext.
	var stored string
	if err := db.QueryRowContext(ctx,
		`SELECT ref_sha256 FROM webhook_tenant_refs WHERE tenant_id = $1`, "tenant-1").Scan(&stored); err != nil {
		t.Fatalf("scan stored: %v", err)
	}
	if stored == ref {
		t.Fatal("stored value equals the plaintext ref")
	}
}

// TestPostgresWebhookRefUnknownMiss proves an unregistered ref is a non-oracle miss
// (ok=false, err=nil) — indistinguishable from any other miss.
func TestPostgresWebhookRefUnknownMiss(t *testing.T) {
	t.Parallel()
	_, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-1")
	ctx := context.Background()

	got, ok, err := s.LookupWebhookRef(ctx, sumOf(t, "never-registered-ref"))
	if err != nil || ok || got != "" {
		t.Fatalf("lookup unknown = (%q, %v, %v), want ('', false, nil)", got, ok, err)
	}
	// An empty hash is also a benign miss, not an error.
	if _, ok, err := s.LookupWebhookRef(ctx, nil); ok || err != nil {
		t.Fatalf("lookup nil = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestPostgresWebhookRefIsolation proves one tenant's ref never resolves to another.
func TestPostgresWebhookRefIsolation(t *testing.T) {
	t.Parallel()
	_, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-a", "tenant-b")
	ctx := context.Background()

	refA, _ := webhookref.Generate()
	refB, _ := webhookref.Generate()
	if err := s.PutWebhookRef(ctx, sumOf(t, refA), "tenant-a"); err != nil {
		t.Fatalf("put a: %v", err)
	}
	if err := s.PutWebhookRef(ctx, sumOf(t, refB), "tenant-b"); err != nil {
		t.Fatalf("put b: %v", err)
	}
	if got, _, _ := s.LookupWebhookRef(ctx, sumOf(t, refA)); got != "tenant-a" {
		t.Fatalf("refA resolved to %q", got)
	}
	if got, _, _ := s.LookupWebhookRef(ctx, sumOf(t, refB)); got != "tenant-b" {
		t.Fatalf("refB resolved to %q", got)
	}
}

// TestPostgresWebhookRefForeignKey proves a ref can only be bound to a real tenant.
func TestPostgresWebhookRefForeignKey(t *testing.T) {
	t.Parallel()
	_, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}) // no tenant seeded
	ref, _ := webhookref.Generate()
	if err := s.PutWebhookRef(context.Background(), sumOf(t, ref), "ghost-tenant"); err == nil {
		t.Fatal("binding a ref to a non-existent tenant must fail the FK constraint")
	}
}

// TestPostgresWebhookRefValidation rejects an empty hash or tenant id.
func TestPostgresWebhookRefValidation(t *testing.T) {
	t.Parallel()
	_, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-1")
	ctx := context.Background()
	ref, _ := webhookref.Generate()
	if err := s.PutWebhookRef(ctx, nil, "tenant-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty hash, got %v", err)
	}
	if err := s.PutWebhookRef(ctx, sumOf(t, ref), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty tenant, got %v", err)
	}
}

// TestPostgresWebhookRefDuplicateIsNoop proves re-putting the SAME ref hash is idempotent
// (INSERT OR IGNORE), not an error on the unique index.
func TestPostgresWebhookRefDuplicateIsNoop(t *testing.T) {
	t.Parallel()
	_, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-1")
	ctx := context.Background()
	ref, _ := webhookref.Generate()
	if err := s.PutWebhookRef(ctx, sumOf(t, ref), "tenant-1"); err != nil {
		t.Fatalf("first put: %v", err)
	}
	if err := s.PutWebhookRef(ctx, sumOf(t, ref), "tenant-1"); err != nil {
		t.Fatalf("second put must be a no-op, got %v", err)
	}
}

// TestPostgresWebhookRefLookupReadError proves a read against a DROPPED table surfaces a
// non-nil error (fail-closed at the authenticator), distinct from a benign miss.
func TestPostgresWebhookRefLookupReadError(t *testing.T) {
	t.Parallel()
	db, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-1")
	ctx := context.Background()
	mustExec(t, db, `DROP TABLE webhook_tenant_refs`)
	ref, _ := webhookref.Generate()
	if _, ok, err := s.LookupWebhookRef(ctx, sumOf(t, ref)); ok || err == nil {
		t.Fatalf("lookup against a dropped table = (%v, %v), want (false, non-nil error)", ok, err)
	}
}

// TestMigration0016Reversible proves the down migration drops the table + index and the
// up recreates it (a clean, backward-compatible round-trip).
func TestMigration0016Reversible(t *testing.T) {
	t.Parallel()
	db, _ := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()})

	// Table exists after up (the fixture already migrated).
	if n := queryInt(t, db, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='webhook_tenant_refs'`); n != 1 {
		t.Fatalf("table missing after up: %d", n)
	}
	// Apply down: table + index gone.
	mustExec(t, db, readMigration(t, "0016_webhook_tenant_refs.down.sql"))
	if n := queryInt(t, db, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='webhook_tenant_refs'`); n != 0 {
		t.Fatalf("table survived down: %d", n)
	}
	// Re-apply up: table back.
	mustExec(t, db, readMigration(t, "0016_webhook_tenant_refs.up.sql"))
	if n := queryInt(t, db, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='webhook_tenant_refs'`); n != 1 {
		t.Fatalf("table missing after re-up: %d", n)
	}
}
