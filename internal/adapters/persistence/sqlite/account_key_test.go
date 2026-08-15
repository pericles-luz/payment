package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/sqlite"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/migrations"
)

// akClock is an advanceable clock for deterministic mint/rotate timestamps.
type akClock struct{ t time.Time }

func (c *akClock) Now() time.Time { return c.t }

// newAccountKeyStore opens a fresh migrated DB, seeds an account (FK parent), and
// returns the raw handle (for at-rest assertions) plus the key store.
func newAccountKeyStore(t *testing.T, clock *akClock, accountIDs ...string) (*sql.DB, *sqlite.AccountKeyStore) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "keys.db")
	db, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := sqlite.Migrate(context.Background(), db, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	repo := sqlite.NewStore(db)
	for _, id := range accountIDs {
		a, err := account.New(id, "Acct "+id, time.Unix(0, 0).UTC())
		if err != nil {
			t.Fatalf("new account: %v", err)
		}
		if err := repo.SaveAccount(context.Background(), a); err != nil {
			t.Fatalf("save account: %v", err)
		}
	}
	return db, sqlite.NewAccountKeyStore(db, clock)
}

func TestSQLiteAccountKeyPutAuthenticate(t *testing.T) {
	t.Parallel()
	_, s := newAccountKeyStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "acct-1")
	ctx := context.Background()

	secret, err := s.PutKey(ctx, "acct-1")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !accountkey.HasSecretShape(secret) {
		t.Fatalf("secret lacks prefix: %q", secret)
	}
	if got, ok := s.AuthenticateAccountKey(ctx, secret); !ok || got != "acct-1" {
		t.Fatalf("authenticate = (%q, %v), want (acct-1, true)", got, ok)
	}
}

// TestSQLiteAccountKeyHashAtRest proves the plaintext is NEVER written: the stored
// key_hash equals sha256(secret) and no row contains the plaintext.
func TestSQLiteAccountKeyHashAtRest(t *testing.T) {
	t.Parallel()
	db, s := newAccountKeyStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "acct-1")
	ctx := context.Background()

	secret, err := s.PutKey(ctx, "acct-1")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	var hash string
	if err := db.QueryRowContext(ctx,
		`SELECT key_hash FROM account_keys WHERE account_id = ? AND active = 1`, "acct-1").
		Scan(&hash); err != nil {
		t.Fatalf("scan hash: %v", err)
	}
	if hash != accountkey.HashSecret(secret) {
		t.Fatal("stored key_hash is not the sha256 of the secret")
	}
	if hash == secret {
		t.Fatal("stored value equals the plaintext")
	}
	// No column anywhere may contain the plaintext.
	var hit int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM account_keys WHERE account_id = ? OR key_hash = ?`, secret, secret).
		Scan(&hit); err != nil {
		t.Fatalf("scan hit: %v", err)
	}
	if hit != 0 {
		t.Fatal("plaintext secret must not appear in any account_keys column")
	}
}

// TestSQLiteAccountKeyRotateSupersedesRow proves rotation invalidates the previous
// secret durably: the old row is marked inactive with rotated_at set, the old secret
// stops authenticating, and exactly one active row remains.
func TestSQLiteAccountKeyRotateSupersedesRow(t *testing.T) {
	t.Parallel()
	clock := &akClock{t: time.Unix(0, 0).UTC()}
	db, s := newAccountKeyStore(t, clock, "acct-1")
	ctx := context.Background()

	first, err := s.PutKey(ctx, "acct-1")
	if err != nil {
		t.Fatalf("first put: %v", err)
	}
	clock.t = time.Unix(3600, 0).UTC()
	second, err := s.Rotate(ctx, "acct-1")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if first == second {
		t.Fatal("rotation must mint a distinct secret")
	}
	if _, ok := s.AuthenticateAccountKey(ctx, first); ok {
		t.Fatal("old secret must no longer authenticate")
	}
	if got, ok := s.AuthenticateAccountKey(ctx, second); !ok || got != "acct-1" {
		t.Fatalf("new secret authenticate = (%q, %v)", got, ok)
	}

	var active, inactive int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM account_keys WHERE account_id = ? AND active = 1`, "acct-1").Scan(&active); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM account_keys WHERE account_id = ? AND active = 0 AND rotated_at IS NOT NULL`,
		"acct-1").Scan(&inactive); err != nil {
		t.Fatalf("count inactive: %v", err)
	}
	if active != 1 {
		t.Fatalf("want exactly 1 active key, got %d", active)
	}
	if inactive != 1 {
		t.Fatalf("want exactly 1 superseded key with rotated_at set, got %d", inactive)
	}
}

func TestSQLiteAccountKeyCreateEqualsRotate(t *testing.T) {
	t.Parallel()
	_, s := newAccountKeyStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "acct-1")
	ctx := context.Background()

	first, err := s.PutKey(ctx, "acct-1")
	if err != nil {
		t.Fatalf("first put: %v", err)
	}
	second, err := s.PutKey(ctx, "acct-1")
	if err != nil {
		t.Fatalf("second put: %v", err)
	}
	if first == second {
		t.Fatal("second PutKey must mint a distinct secret (create==rotate)")
	}
	if _, ok := s.AuthenticateAccountKey(ctx, first); ok {
		t.Fatal("first secret must be invalidated")
	}
	if _, ok := s.AuthenticateAccountKey(ctx, second); !ok {
		t.Fatal("second secret must authenticate")
	}
}

func TestSQLiteAccountKeyValidationAndMisses(t *testing.T) {
	t.Parallel()
	_, s := newAccountKeyStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "acct-1")
	ctx := context.Background()

	if _, err := s.PutKey(ctx, ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for empty account id, got %v", err)
	}
	if _, ok := s.AuthenticateAccountKey(ctx, "ak_never-issued"); ok {
		t.Fatal("unknown secret must not authenticate")
	}
	if _, ok := s.AuthenticateAccountKey(ctx, ""); ok {
		t.Fatal("empty secret must not authenticate")
	}
}

// TestSQLiteAccountKeyForeignKey proves a key can only be minted for a real account
// (FK enforced) — a defence-in-depth check that keys never dangle.
func TestSQLiteAccountKeyForeignKey(t *testing.T) {
	t.Parallel()
	_, s := newAccountKeyStore(t, &akClock{t: time.Unix(0, 0).UTC()}) // no account seeded
	if _, err := s.PutKey(context.Background(), "ghost-account"); err == nil {
		t.Fatal("minting a key for a non-existent account must fail the FK constraint")
	}
}

// TestSQLiteAccountKeyIsolation proves one account's secret never resolves to another.
func TestSQLiteAccountKeyIsolation(t *testing.T) {
	t.Parallel()
	_, s := newAccountKeyStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "acct-a", "acct-b")
	ctx := context.Background()

	sa, err := s.PutKey(ctx, "acct-a")
	if err != nil {
		t.Fatalf("put a: %v", err)
	}
	sb, err := s.PutKey(ctx, "acct-b")
	if err != nil {
		t.Fatalf("put b: %v", err)
	}
	if got, _ := s.AuthenticateAccountKey(ctx, sa); got != "acct-a" {
		t.Fatalf("secret a resolved to %q", got)
	}
	if got, _ := s.AuthenticateAccountKey(ctx, sb); got != "acct-b" {
		t.Fatalf("secret b resolved to %q", got)
	}
}
