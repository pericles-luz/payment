package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
	migrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// fixedClock is a deterministic ports.Clock for the vault adapters' updated_at.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// testCipher builds an AES-256 cipher from a fixed 32-byte key for the vault tests.
func testCipher(t *testing.T) *secret.Cipher {
	t.Helper()
	key := bytes.Repeat([]byte{0xA5}, 32)
	c, err := secret.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	return c
}

// openVaultDB opens a fresh migrated DB at a temp-dir DSN (a real file, so a
// "restart" — reopening the same DSN — exercises real persistence, not a shared
// in-memory handle). It returns the DSN so a test can reopen it.
func openVaultDB(t *testing.T) (string, *sql.DB) {
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
	return dsn, db
}

func newCredentialVault(t *testing.T, db *sql.DB) *postgres.CredentialVault {
	t.Helper()
	return postgres.NewCredentialVault(db, testCipher(t), fixedClock{t: time.Unix(1700000000, 0).UTC()})
}

// TestCredentialVaultRoundTripSurvivesRestart is the core acceptance criterion: a
// credential written via the port is readable after the store is recreated over the
// SAME database file (the persistence "restart" the CEO asked about).
func TestCredentialVaultRoundTripSurvivesRestart(t *testing.T) {
	t.Parallel()
	dsn, db := openVaultDB(t)
	ctx := context.Background()

	if err := newCredentialVault(t, db).SetBankCredential(ctx, "tnt-1", "c6", "client-1", "s3cr3t-value"); err != nil {
		t.Fatalf("set: %v", err)
	}
	_ = db.Close()

	// Reopen the same DSN with a brand-new store + cipher (same key) — a process restart.
	db2, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	got, err := newCredentialVault(t, db2).GetBankCredential(ctx, "tnt-1", "c6")
	if err != nil {
		t.Fatalf("get after restart: %v", err)
	}
	if got.ClientID != "client-1" || got.Secret != "s3cr3t-value" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.TenantID != "tnt-1" || got.BankID != "c6" {
		t.Fatalf("identity mismatch: %+v", got)
	}
}

// TestCredentialVaultEncryptedAtRest asserts the durable column holds ciphertext, not
// the plaintext secret/creditor key (threat C1/C4).
func TestCredentialVaultEncryptedAtRest(t *testing.T) {
	t.Parallel()
	dsn, db := openVaultDB(t)
	ctx := context.Background()
	v := newCredentialVault(t, db)
	if err := v.SetBankCredential(ctx, "tnt-1", "c6", "client-1", "PLAINTEXT-SECRET"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := v.SetCreditorKey(ctx, "tnt-1", "12345678000199"); err != nil {
		t.Fatalf("set creditor: %v", err)
	}

	var secSealed, ckSealed []byte
	// Read the raw stored bytes back over the same file.
	rdb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	if err := rdb.QueryRowContext(ctx,
		`SELECT secret_sealed, creditor_key_sealed FROM bank_credentials WHERE tenant_id = $1 AND bank_id = $2`,
		"tnt-1", "c6").Scan(&secSealed, &ckSealed); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if bytes.Contains(secSealed, []byte("PLAINTEXT-SECRET")) {
		t.Fatal("secret stored in plaintext at rest")
	}
	if bytes.Contains(ckSealed, []byte("12345678000199")) {
		t.Fatal("creditor key stored in plaintext at rest")
	}
	// And it decrypts back correctly through the port.
	got, err := v.GetBankCredential(ctx, "tnt-1", "c6")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Secret != "PLAINTEXT-SECRET" || got.CreditorKey != "12345678000199" {
		t.Fatalf("decrypt mismatch: %+v", got)
	}
}

// TestCredentialVaultWrongKeyFailsClosed: a vault opened with a DIFFERENT KEK cannot
// decrypt a secret sealed under the original key — GCM authentication fails, so the
// read returns an error rather than silently yielding garbage plaintext (a KEK
// rotation/misconfiguration must fail closed, never fail open).
func TestCredentialVaultWrongKeyFailsClosed(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	if err := newCredentialVault(t, db).SetBankCredential(ctx, "tnt-1", "c6", "cid", "sec"); err != nil {
		t.Fatalf("set: %v", err)
	}
	wrongKey := bytes.Repeat([]byte{0xB6}, 32)
	wrongCipher, err := secret.NewCipher(wrongKey)
	if err != nil {
		t.Fatalf("wrong cipher: %v", err)
	}
	other := postgres.NewCredentialVault(db, wrongCipher, fixedClock{t: time.Unix(1700000000, 0).UTC()})
	if _, err := other.GetBankCredential(ctx, "tnt-1", "c6"); err == nil {
		t.Fatal("wrong-key read must fail, not return garbage plaintext")
	}
}

// TestCredentialVaultGetExactMatchNoFallback: a miss on tenant OR bank returns
// ErrNotFound and never resolves to another slot (deny-by-default; T1/T2).
func TestCredentialVaultGetExactMatchNoFallback(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCredentialVault(t, db)
	if err := v.SetBankCredential(ctx, "tnt-1", "c6", "cid", "sec"); err != nil {
		t.Fatalf("set: %v", err)
	}
	cases := []struct{ tenant, bank string }{
		{"tnt-2", "c6"},    // other tenant
		{"tnt-1", "other"}, // other bank
		{"missing", "c6"},  // unknown
	}
	for _, c := range cases {
		if _, err := v.GetBankCredential(ctx, c.tenant, c.bank); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("(%s,%s): want ErrNotFound, got %v", c.tenant, c.bank, err)
		}
	}
}

// TestCredentialVaultEmptyBankDefaultsToC6: an empty bankID resolves to BankIDC6 on
// both write and read (retro-compat).
func TestCredentialVaultEmptyBankDefaultsToC6(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCredentialVault(t, db)
	if err := v.SetBankCredential(ctx, "tnt-1", "", "cid", "sec"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := v.GetBankCredential(ctx, "tnt-1", ports.BankIDC6)
	if err != nil {
		t.Fatalf("get c6: %v", err)
	}
	if got.BankID != ports.BankIDC6 {
		t.Fatalf("bank not defaulted: %q", got.BankID)
	}
}

// TestCredentialVaultRotatePreservesCreditorKey: rotating the secret via
// SetBankCredential must NOT wipe a previously registered creditor key (SIN-66092).
func TestCredentialVaultRotatePreservesCreditorKey(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCredentialVault(t, db)
	if err := v.SetBankCredential(ctx, "tnt-1", "c6", "cid", "sec-1"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := v.SetCreditorKey(ctx, "tnt-1", "12345678000199"); err != nil {
		t.Fatalf("set creditor: %v", err)
	}
	// Rotate the secret.
	if err := v.SetBankCredential(ctx, "tnt-1", "c6", "cid", "sec-2"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	got, err := v.GetBankCredential(ctx, "tnt-1", "c6")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Secret != "sec-2" {
		t.Fatalf("secret not rotated: %q", got.Secret)
	}
	if got.CreditorKey != "12345678000199" {
		t.Fatalf("creditor key wiped by rotation: %q", got.CreditorKey)
	}
}

// TestCredentialVaultSetCreditorKeyRequiresExisting: a creditor key without an
// existing bank identity is refused (ErrNotFound); malformed/empty are validation
// errors that never echo the value.
func TestCredentialVaultSetCreditorKeyGuards(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCredentialVault(t, db)

	if err := v.SetCreditorKey(ctx, "no-cred", "12345678000199"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("no existing credential: want ErrNotFound, got %v", err)
	}

	if err := v.SetBankCredential(ctx, "tnt-1", "c6", "cid", "sec"); err != nil {
		t.Fatalf("set: %v", err)
	}
	var ve *shared.ValidationError
	if err := v.SetCreditorKey(ctx, "tnt-1", ""); !errors.As(err, &ve) {
		t.Fatalf("empty key: want ValidationError, got %v", err)
	}
	if err := v.SetCreditorKey(ctx, "tnt-1", "not a pix key"); !errors.As(err, &ve) {
		t.Fatalf("malformed key: want ValidationError, got %v", err)
	}
	if err := v.SetCreditorKey(ctx, "", "12345678000199"); !errors.As(err, &ve) {
		t.Fatalf("empty tenant: want ValidationError, got %v", err)
	}
}

// TestCredentialVaultSetValidation: empty tenant/client/secret are rejected without
// persisting anything.
func TestCredentialVaultSetValidation(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCredentialVault(t, db)
	var ve *shared.ValidationError
	cases := []struct {
		name                      string
		tenant, bank, client, sec string
	}{
		{"empty tenant", "", "c6", "cid", "sec"},
		{"empty client", "t", "c6", "", "sec"},
		{"empty secret", "t", "c6", "cid", ""},
	}
	for _, c := range cases {
		if err := v.SetBankCredential(ctx, c.tenant, c.bank, c.client, c.sec); !errors.As(err, &ve) {
			t.Fatalf("%s: want ValidationError, got %v", c.name, err)
		}
	}
}

// TestCredentialVaultDeleteIdempotent: deleting an absent pair is a no-op; deleting a
// present pair removes the row (Get → NotFound).
func TestCredentialVaultDeleteIdempotent(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCredentialVault(t, db)

	if err := v.DeleteBankCredential(ctx, "ghost", "c6"); err != nil {
		t.Fatalf("delete absent: %v", err)
	}
	if err := v.SetBankCredential(ctx, "tnt-1", "c6", "cid", "sec"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := v.DeleteBankCredential(ctx, "tnt-1", ""); err != nil { // empty bank → c6
		t.Fatalf("delete present: %v", err)
	}
	if _, err := v.GetBankCredential(ctx, "tnt-1", "c6"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
	// Second delete is still a harmless no-op.
	if err := v.DeleteBankCredential(ctx, "tnt-1", "c6"); err != nil {
		t.Fatalf("delete again: %v", err)
	}
}

// TestCredentialVaultSeedBootstrap: Seed inserts an absent env credential once, and a
// re-seed with a DIFFERENT secret must NOT overwrite the runtime-durable row
// (env-as-bootstrap, DB-as-durable-source). Incomplete env entries are skipped.
func TestCredentialVaultSeedBootstrap(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCredentialVault(t, db)

	// Map keyed like secret.NewStore: an empty TenantID takes the map key.
	seed := map[string]ports.BankCredential{
		"tnt-1":      {ClientID: "cid-1", Secret: "env-secret", BankID: "c6"},
		"tnt-2":      {ClientID: "cid-2", Secret: "env-secret-2"}, // empty bank → c6
		"incomplete": {ClientID: "cid-x"},                         // no secret → skipped
	}
	if err := v.Seed(ctx, seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := v.GetBankCredential(ctx, "tnt-1", "c6")
	if err != nil || got.Secret != "env-secret" {
		t.Fatalf("seeded tnt-1: %+v err=%v", got, err)
	}
	if _, err := v.GetBankCredential(ctx, "incomplete", "c6"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("incomplete should be skipped, got err=%v", err)
	}

	// Simulate a runtime edit, then re-seed from env with a stale value: the edit wins.
	if err := v.SetBankCredential(ctx, "tnt-1", "c6", "cid-1", "runtime-edited"); err != nil {
		t.Fatalf("runtime edit: %v", err)
	}
	if err := v.Seed(ctx, seed); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	got, err = v.GetBankCredential(ctx, "tnt-1", "c6")
	if err != nil {
		t.Fatalf("get after reseed: %v", err)
	}
	if got.Secret != "runtime-edited" {
		t.Fatalf("env re-seed clobbered the durable runtime edit: %q", got.Secret)
	}
}

// TestCredentialVaultListTenantsWithC6Credential verifies the enumerator returns only
// C6-credentialed tenants, without exposing secrets.
func TestCredentialVaultListTenantsWithC6Credential(t *testing.T) {
	ctx := context.Background()
	_, db := openVaultDB(t)
	v := newCredentialVault(t, db)

	// Empty initially.
	ids, err := v.ListTenantsWithC6Credential(ctx)
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected empty, got %v", ids)
	}

	// Add two C6 tenants.
	if err := v.SetBankCredential(ctx, "tnt-a", "c6", "cid-a", "sec-a"); err != nil {
		t.Fatalf("set tnt-a: %v", err)
	}
	if err := v.SetBankCredential(ctx, "tnt-b", "c6", "cid-b", "sec-b"); err != nil {
		t.Fatalf("set tnt-b: %v", err)
	}

	ids, err = v.ListTenantsWithC6Credential(ctx)
	if err != nil {
		t.Fatalf("list after inserts: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 tenants, got %v", ids)
	}
	got := map[string]bool{}
	for _, id := range ids {
		got[id] = true
	}
	for _, want := range []string{"tnt-a", "tnt-b"} {
		if !got[want] {
			t.Errorf("missing %q in result", want)
		}
	}
}
