package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/webhookref"
)

// TestPostgresWebhookRefSupersede proves PutWebhookRef has SUPERSEDE semantics (B1): a
// second ref for the same tenant revokes the first, so the tenant ends with EXACTLY ONE
// active ref (AC#1). The superseded ref stops resolving; the new one resolves.
func TestPostgresWebhookRefSupersede(t *testing.T) {
	t.Parallel()
	db, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-1")
	ctx := context.Background()

	ref1, _ := webhookref.Generate()
	ref2, _ := webhookref.Generate()
	if err := s.PutWebhookRef(ctx, sumOf(t, ref1), "tenant-1"); err != nil {
		t.Fatalf("put ref1: %v", err)
	}
	if err := s.PutWebhookRef(ctx, sumOf(t, ref2), "tenant-1"); err != nil {
		t.Fatalf("put ref2: %v", err)
	}
	// ref1 superseded → non-oracle miss; ref2 active → resolves.
	if _, ok, err := s.LookupWebhookRef(ctx, sumOf(t, ref1)); ok || err != nil {
		t.Fatalf("superseded ref1 = (%v, %v), want (false, nil)", ok, err)
	}
	if got, ok, err := s.LookupWebhookRef(ctx, sumOf(t, ref2)); !ok || err != nil || got != "tenant-1" {
		t.Fatalf("active ref2 = (%q, %v, %v), want (tenant-1, true, nil)", got, ok, err)
	}
	// Exactly ONE active row; the superseded row is retained (soft-deleted) for audit.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM webhook_tenant_refs WHERE tenant_id='tenant-1' AND revoked_at IS NULL`); n != 1 {
		t.Fatalf("active rows = %d, want 1", n)
	}
	if n := queryInt(t, db, `SELECT COUNT(*) FROM webhook_tenant_refs WHERE tenant_id='tenant-1'`); n != 2 {
		t.Fatalf("total rows = %d, want 2 (superseded row retained for audit)", n)
	}
}

// TestPostgresWebhookRefRevoke proves RevokeWebhookRefs soft-deletes the tenant's active
// ref (AC#2): after revoke the ref no longer resolves, the row is retained, and a second
// revoke is an idempotent no-op returning 0.
func TestPostgresWebhookRefRevoke(t *testing.T) {
	t.Parallel()
	db, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-1")
	ctx := context.Background()

	ref, _ := webhookref.Generate()
	if err := s.PutWebhookRef(ctx, sumOf(t, ref), "tenant-1"); err != nil {
		t.Fatalf("put: %v", err)
	}
	n, err := s.RevokeWebhookRefs(ctx, "tenant-1")
	if err != nil || n != 1 {
		t.Fatalf("revoke = (%d, %v), want (1, nil)", n, err)
	}
	if _, ok, err := s.LookupWebhookRef(ctx, sumOf(t, ref)); ok || err != nil {
		t.Fatalf("revoked ref = (%v, %v), want (false, nil)", ok, err)
	}
	// Soft-delete: the row is still there, just stamped revoked_at.
	if n := queryInt(t, db, `SELECT COUNT(*) FROM webhook_tenant_refs WHERE tenant_id='tenant-1' AND revoked_at IS NOT NULL`); n != 1 {
		t.Fatalf("revoked (retained) rows = %d, want 1", n)
	}
	// Idempotent: nothing active to revoke → 0.
	if n, err := s.RevokeWebhookRefs(ctx, "tenant-1"); err != nil || n != 0 {
		t.Fatalf("second revoke = (%d, %v), want (0, nil)", n, err)
	}
}

// TestPostgresWebhookRefRevokeValidation rejects an empty tenant id.
func TestPostgresWebhookRefRevokeValidation(t *testing.T) {
	t.Parallel()
	_, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-1")
	if _, err := s.RevokeWebhookRefs(context.Background(), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty tenant, got %v", err)
	}
}

// TestPostgresWebhookRefSupersedeIsolation proves superseding one tenant's ref never
// revokes another tenant's active ref.
func TestPostgresWebhookRefSupersedeIsolation(t *testing.T) {
	t.Parallel()
	_, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-a", "tenant-b")
	ctx := context.Background()

	refA, _ := webhookref.Generate()
	refB, _ := webhookref.Generate()
	refA2, _ := webhookref.Generate()
	if err := s.PutWebhookRef(ctx, sumOf(t, refA), "tenant-a"); err != nil {
		t.Fatalf("put a: %v", err)
	}
	if err := s.PutWebhookRef(ctx, sumOf(t, refB), "tenant-b"); err != nil {
		t.Fatalf("put b: %v", err)
	}
	// Supersede tenant-a; tenant-b must be untouched.
	if err := s.PutWebhookRef(ctx, sumOf(t, refA2), "tenant-a"); err != nil {
		t.Fatalf("supersede a: %v", err)
	}
	if got, ok, _ := s.LookupWebhookRef(ctx, sumOf(t, refB)); !ok || got != "tenant-b" {
		t.Fatalf("tenant-b ref must survive tenant-a supersede, got (%q, %v)", got, ok)
	}
	if got, ok, _ := s.LookupWebhookRef(ctx, sumOf(t, refA2)); !ok || got != "tenant-a" {
		t.Fatalf("tenant-a new ref = (%q, %v), want (tenant-a, true)", got, ok)
	}
}

// TestPostgresWebhookRefReactivateOnRePut proves re-putting a PREVIOUSLY REVOKED hash
// re-activates it (ON CONFLICT clears revoked_at) — a defensive edge; a fresh 256-bit
// ref never actually collides.
func TestPostgresWebhookRefReactivateOnRePut(t *testing.T) {
	t.Parallel()
	_, s := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "tenant-1")
	ctx := context.Background()

	ref, _ := webhookref.Generate()
	if err := s.PutWebhookRef(ctx, sumOf(t, ref), "tenant-1"); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := s.RevokeWebhookRefs(ctx, "tenant-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok, _ := s.LookupWebhookRef(ctx, sumOf(t, ref)); ok {
		t.Fatal("ref should be revoked before re-put")
	}
	if err := s.PutWebhookRef(ctx, sumOf(t, ref), "tenant-1"); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	if got, ok, err := s.LookupWebhookRef(ctx, sumOf(t, ref)); !ok || err != nil || got != "tenant-1" {
		t.Fatalf("re-put ref = (%q, %v, %v), want (tenant-1, true, nil)", got, ok, err)
	}
}

// TestMigration0017Reversible proves the 0017 down migration drops the revoked_at column
// + active index and the up re-adds them (a clean, backward-compatible round-trip). The
// column is present after the fixture's up-migration.
func TestMigration0017Reversible(t *testing.T) {
	t.Parallel()
	db, _ := newWebhookRefStore(t, &akClock{t: time.Unix(0, 0).UTC()})

	hasRevokedCol := func() bool {
		rows, err := db.QueryContext(context.Background(), `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'webhook_tenant_refs'`)
		if err != nil {
			t.Fatalf("query columns: %v", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatalf("scan column name: %v", err)
			}
			if name == "revoked_at" {
				return true
			}
		}
		return false
	}

	if !hasRevokedCol() {
		t.Fatal("revoked_at column missing after up")
	}
	mustExec(t, db, readMigration(t, "0017_webhook_ref_revocation.down.sql"))
	if hasRevokedCol() {
		t.Fatal("revoked_at column survived down")
	}
	mustExec(t, db, readMigration(t, "0017_webhook_ref_revocation.up.sql"))
	if !hasRevokedCol() {
		t.Fatal("revoked_at column missing after re-up")
	}
}
