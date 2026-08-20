package postgres_test

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/payment"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// TestClosedDBPropagatesErrors exercises every method's error branch by closing
// the underlying database first.
func TestClosedDBPropagatesErrors(t *testing.T) {
	t.Parallel()
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := postgres.Migrate(context.Background(), db, fstest.MapFS{}); err != nil {
		t.Fatalf("migrate empty: %v", err)
	}
	s := postgres.NewStore(db)
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
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	badFS := fstest.MapFS{
		"0001_bad.up.sql": &fstest.MapFile{Data: []byte("THIS IS NOT SQL;")},
	}
	if err := postgres.Migrate(context.Background(), db, badFS); err == nil {
		t.Fatal("expected migration error for bad SQL")
	}
}

// TestMigrateClosedDB covers the early error branches of the ledgered runner: a
// closed database fails the first statement (ensuring schema_migrations).
func TestMigrateClosedDB(t *testing.T) {
	t.Parallel()
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := postgres.Migrate(context.Background(), db, migrations.FS); err == nil {
		t.Fatal("expected migration error on closed db")
	}
}

// TestMigrateReadFileError covers the read-migration error branch: the runner
// lists a *.up.sql entry it then cannot read.
func TestMigrateReadFileError(t *testing.T) {
	t.Parallel()
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := postgres.Migrate(context.Background(), db, listOnlyFS{}); err == nil {
		t.Fatal("expected migration error when a listed file cannot be read")
	}
}

// listOnlyFS lists one *.up.sql file (via ReadDirFS) but errors on ReadFile (via
// ReadFileFS), so fs.ReadDir succeeds and fs.ReadFile fails — exactly the path the
// runner takes between discovering a migration and reading its bytes.
type listOnlyFS struct{}

func (listOnlyFS) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }
func (listOnlyFS) ReadDir(string) ([]fs.DirEntry, error) {
	return []fs.DirEntry{upEntry{}}, nil
}
func (listOnlyFS) ReadFile(string) ([]byte, error) { return nil, errBoomRead }

var errBoomRead = errors.New("boom: cannot read migration")

type upEntry struct{}

func (upEntry) Name() string               { return "0001_x.up.sql" }
func (upEntry) IsDir() bool                { return false }
func (upEntry) Type() fs.FileMode          { return 0 }
func (upEntry) Info() (fs.FileInfo, error) { return nil, nil }

// TestParseTimeFallback covers the parseTime error branch: a row with a malformed
// timestamp rehydrates to the zero time rather than failing the read.
func TestParseTimeFallback(t *testing.T) {
	t.Parallel()
	dsn := testDSN(t)
	db, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := postgres.Migrate(context.Background(), db, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Insert a tenant with a non-RFC3339 created_at directly.
	if _, err := db.Exec(`INSERT INTO tenants (id, name, active, created_at) VALUES ($1, $2, $3, $4)`,
		"t1", "Acme", 1, "not-a-timestamp"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	s := postgres.NewStore(db)
	got, err := s.FindTenantByID(context.Background(), "t1")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if !got.CreatedAt().IsZero() {
		t.Fatalf("expected zero time fallback, got %v", got.CreatedAt())
	}
}
