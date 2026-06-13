package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/migrations"
)

// TestClosedDBPropagatesErrors exercises every method's error branch by closing
// the underlying database first.
func TestClosedDBPropagatesErrors(t *testing.T) {
	t.Parallel()
	dsn := filepath.Join(t.TempDir(), "closed.db")
	db, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := sqlite.Migrate(context.Background(), db, fstest.MapFS{}); err != nil {
		t.Fatalf("migrate empty: %v", err)
	}
	s := sqlite.NewStore(db)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ctx := context.Background()
	now := time.Unix(1, 0).UTC()
	tn, _ := tenant.New("t1", "Acme", now)
	p, _ := payment.New("p1", "t1", "pix.create", "k1", mustMoney(t), now)
	price, _ := billing.NewEndpointPricing("t1", "pix.create", 10)
	entry, _ := billing.NewLedgerEntry("l1", "t1", "pix.create", "p1", 10, now)

	checks := []struct {
		name string
		fn   func() error
	}{
		{"SaveTenant", func() error { return s.SaveTenant(ctx, tn) }},
		{"FindTenantByID", func() error { _, e := s.FindTenantByID(ctx, "t1"); return e }},
		{"SavePayment", func() error { return s.SavePayment(ctx, p) }},
		{"FindPaymentByID", func() error { _, e := s.FindPaymentByID(ctx, "t1", "p1"); return e }},
		{"FindPaymentByIdempotencyKey", func() error { _, e := s.FindPaymentByIdempotencyKey(ctx, "t1", "k1"); return e }},
		{"FindPaymentByTxID", func() error { _, e := s.FindPaymentByTxID(ctx, "t1", "tx1"); return e }},
		{"GetEndpointPrice", func() error { _, e := s.GetEndpointPrice(ctx, "t1", "pix.create"); return e }},
		{"UpsertEndpointPrice", func() error { return s.UpsertEndpointPrice(ctx, price) }},
		{"AppendLedgerEntry", func() error { return s.AppendLedgerEntry(ctx, entry) }},
		{"MarkProcessed", func() error { _, e := s.MarkProcessed(ctx, "t1", "e1"); return e }},
	}
	for _, c := range checks {
		if err := c.fn(); err == nil {
			t.Errorf("%s: expected error on closed db", c.name)
		}
	}
}

// TestMigrateBadSQL covers the apply-migration error branch.
func TestMigrateBadSQL(t *testing.T) {
	t.Parallel()
	dsn := filepath.Join(t.TempDir(), "bad.db")
	db, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	badFS := fstest.MapFS{
		"0001_bad.up.sql": &fstest.MapFile{Data: []byte("THIS IS NOT SQL;")},
	}
	if err := sqlite.Migrate(context.Background(), db, badFS); err == nil {
		t.Fatal("expected migration error for bad SQL")
	}
}

// TestParseTimeFallback covers the parseTime error branch: a row with a malformed
// timestamp rehydrates to the zero time rather than failing the read.
func TestParseTimeFallback(t *testing.T) {
	t.Parallel()
	dsn := filepath.Join(t.TempDir(), "ts.db")
	db, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := sqlite.Migrate(context.Background(), db, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Insert a tenant with a non-RFC3339 created_at directly.
	if _, err := db.Exec(`INSERT INTO tenants (id, name, active, created_at) VALUES (?, ?, ?, ?)`,
		"t1", "Acme", 1, "not-a-timestamp"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	s := sqlite.NewStore(db)
	got, err := s.FindTenantByID(context.Background(), "t1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if !got.CreatedAt().IsZero() {
		t.Fatalf("expected zero time fallback, got %v", got.CreatedAt())
	}
}
