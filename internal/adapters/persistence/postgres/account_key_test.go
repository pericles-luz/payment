package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/account"
	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// akClock is an advanceable clock for deterministic mint/rotate timestamps.
type akClock struct{ t time.Time }

func (c *akClock) Now() time.Time { return c.t }

// newAccountKeyStore opens a fresh migrated DB, seeds an account (FK parent), and
// returns the raw handle (for at-rest assertions) plus the key store.
func newAccountKeyStore(t *testing.T, clock *akClock, accountIDs ...string) (*sql.DB, *postgres.AccountKeyStore) {
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
	for _, id := range accountIDs {
		a, err := account.New(id, "Acct "+id, time.Unix(0, 0).UTC())
		if err != nil {
			t.Fatalf("new account: %v", err)
		}
		if err := repo.SaveAccount(context.Background(), a); err != nil {
			t.Fatalf("save account: %v", err)
		}
	}
	return db, postgres.NewAccountKeyStore(db, clock)
}

func TestPostgresAccountKeyPutAuthenticate(t *testing.T) {
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

// TestPostgresAccountKeyHashAtRest proves the plaintext is NEVER written: the stored
// key_hash equals sha256(secret) and no row contains the plaintext.
func TestPostgresAccountKeyHashAtRest(t *testing.T) {
	t.Parallel()
	db, s := newAccountKeyStore(t, &akClock{t: time.Unix(0, 0).UTC()}, "acct-1")
	ctx := context.Background()

	secret, err := s.PutKey(ctx, "acct-1")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	var hash string
	if err := db.QueryRowContext(ctx,
		`SELECT key_hash FROM account_keys WHERE account_id = $1 AND active = 1`, "acct-1").
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
		`SELECT COUNT(*) FROM account_keys WHERE account_id = $1 OR key_hash = $2`, secret, secret).
		Scan(&hit); err != nil {
		t.Fatalf("scan hit: %v", err)
	}
	if hit != 0 {
		t.Fatal("plaintext secret must not appear in any account_keys column")
	}
}

// TestPostgresAccountKeyRotateSupersedesRow proves rotation invalidates the previous
// secret durably: the old row is marked inactive with rotated_at set, the old secret
// stops authenticating, and exactly one active row remains.
func TestPostgresAccountKeyRotateSupersedesRow(t *testing.T) {
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
		`SELECT COUNT(*) FROM account_keys WHERE account_id = $1 AND active = 1`, "acct-1").Scan(&active); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM account_keys WHERE account_id = $1 AND active = 0 AND rotated_at IS NOT NULL`,
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

func TestPostgresAccountKeyCreateEqualsRotate(t *testing.T) {
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

func TestPostgresAccountKeyValidationAndMisses(t *testing.T) {
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

// TestPostgresAccountKeyForeignKey proves a key can only be minted for a real account
// (FK enforced) — a defence-in-depth check that keys never dangle.
func TestPostgresAccountKeyForeignKey(t *testing.T) {
	t.Parallel()
	_, s := newAccountKeyStore(t, &akClock{t: time.Unix(0, 0).UTC()}) // no account seeded
	if _, err := s.PutKey(context.Background(), "ghost-account"); err == nil {
		t.Fatal("minting a key for a non-existent account must fail the FK constraint")
	}
}

// TestPostgresAccountKeyIsolation proves one account's secret never resolves to another.
func TestPostgresAccountKeyIsolation(t *testing.T) {
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
