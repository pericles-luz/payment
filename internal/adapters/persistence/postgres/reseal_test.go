package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// cipherWithKey builds a distinct AES-256 cipher (each byte = b) for rotation tests.
func cipherWithKey(t *testing.T, b byte) *secret.Cipher {
	t.Helper()
	c, err := secret.NewCipher(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	return c
}

func credVaultWith(t *testing.T, db *sql.DB, c *secret.Cipher) *postgres.CredentialVault {
	t.Helper()
	return postgres.NewCredentialVault(db, c, fixedClock{t: time.Unix(1700000000, 0).UTC()})
}

func certVaultWith(t *testing.T, db *sql.DB, c *secret.Cipher) *postgres.CertificateVault {
	t.Helper()
	return postgres.NewCertificateVault(db, c, fixedClock{t: time.Unix(1700000000, 0).UTC()})
}

// TestCredentialBlobFromAnotherRowDoesNotOpen is the SIN-69369 acceptance criterion:
// a sealed secret relocated (copied) into a different (tenant, bank) row no longer
// decrypts, because the blob is cryptographically bound to its original row's AAD.
func TestCredentialBlobFromAnotherRowDoesNotOpen(t *testing.T) {
	t.Parallel()
	dsn, db := openVaultDB(t)
	ctx := context.Background()
	v := newCredentialVault(t, db) // fixed 0xA5 cipher

	if err := v.SetBankCredential(ctx, "tenant-a", "c6", "client-a", "secret-a"); err != nil {
		t.Fatalf("set a: %v", err)
	}
	if err := v.SetBankCredential(ctx, "tenant-b", "c6", "client-b", "secret-b"); err != nil {
		t.Fatalf("set b: %v", err)
	}

	// Relocate tenant-a's sealed secret into tenant-b's row via raw SQL (the
	// confused-deputy / row-swap the AAD binding defends against).
	rdb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	var aSealed []byte
	if err := rdb.QueryRowContext(ctx,
		`SELECT secret_sealed FROM bank_credentials WHERE tenant_id = $1 AND bank_id = $2`,
		"tenant-a", "c6").Scan(&aSealed); err != nil {
		t.Fatalf("read a sealed: %v", err)
	}
	if _, err := rdb.ExecContext(ctx,
		`UPDATE bank_credentials SET secret_sealed = $1 WHERE tenant_id = $2 AND bank_id = $3`,
		aSealed, "tenant-b", "c6"); err != nil {
		t.Fatalf("relocate: %v", err)
	}

	// tenant-b's row now carries tenant-a's ciphertext: it must fail to open, never
	// leak "secret-a" under tenant-b.
	if _, err := v.GetBankCredential(ctx, "tenant-b", "c6"); err == nil {
		t.Fatal("relocated blob must not open under a different row")
	}
	// The untouched original row still opens.
	got, err := v.GetBankCredential(ctx, "tenant-a", "c6")
	if err != nil {
		t.Fatalf("original row must still open: %v", err)
	}
	if got.Secret != "secret-a" {
		t.Fatalf("original secret mismatch: %q", got.Secret)
	}
}

// TestResealRotatesCredentialKEK: after re-sealing from the old key to a new key,
// the rows open with the new cipher and no longer with the old one.
func TestResealRotatesCredentialKEK(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	oldC := cipherWithKey(t, 0x01)
	newC := cipherWithKey(t, 0x02)

	oldV := credVaultWith(t, db, oldC)
	if err := oldV.SetBankCredential(ctx, "tnt", "c6", "cid", "the-secret"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := oldV.SetCreditorKey(ctx, "tnt", "pix-key@example.com"); err != nil {
		t.Fatalf("set ck: %v", err)
	}

	// Re-seal with the NEW cipher, opening with the OLD one.
	newV := credVaultWith(t, db, newC)
	n, err := newV.Reseal(ctx, oldC)
	if err != nil {
		t.Fatalf("reseal: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 row resealed, got %d", n)
	}

	got, err := newV.GetBankCredential(ctx, "tnt", "c6")
	if err != nil {
		t.Fatalf("read after reseal (new key): %v", err)
	}
	if got.Secret != "the-secret" || got.CreditorKey != "pix-key@example.com" {
		t.Fatalf("plaintext not preserved: %+v", got)
	}
	// The old cipher must no longer open the rewritten rows.
	if _, err := oldV.GetBankCredential(ctx, "tnt", "c6"); err == nil {
		t.Fatal("old key must not open rows after rotation")
	}
}

// TestResealUpgradesLegacyNilAAD proves the migration path: a blob sealed BEFORE
// row-binding (nil AAD) is transparently upgraded to an AAD-bound blob by the
// re-seal, and is then readable through the normal (AAD-bound) read path.
func TestResealUpgradesLegacyNilAAD(t *testing.T) {
	t.Parallel()
	dsn, db := openVaultDB(t)
	ctx := context.Background()
	key := cipherWithKey(t, 0x03)

	// Simulate a pre-SIN-69369 row: seal with nil AAD and raw-insert it.
	legacy, err := key.Seal([]byte("legacy-secret"))
	if err != nil {
		t.Fatalf("legacy seal: %v", err)
	}
	rdb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	if _, err := rdb.ExecContext(ctx,
		`INSERT INTO bank_credentials (tenant_id, bank_id, client_id, secret_sealed, creditor_key_sealed, updated_at)
		 VALUES ($1, $2, $3, $4, NULL, $5)`,
		"tnt", "c6", "cid", legacy, "2023-11-14T22:13:20Z"); err != nil {
		t.Fatalf("raw insert legacy: %v", err)
	}

	v := credVaultWith(t, db, key)
	// The AAD-bound read path cannot open the legacy nil-AAD blob yet.
	if _, err := v.GetBankCredential(ctx, "tnt", "c6"); err == nil {
		t.Fatal("legacy nil-AAD blob must not open on the AAD-bound read path before migration")
	}
	// Re-seal to the SAME key upgrades the AAD binding.
	if _, err := v.Reseal(ctx, key); err != nil {
		t.Fatalf("reseal (AAD migration): %v", err)
	}
	got, err := v.GetBankCredential(ctx, "tnt", "c6")
	if err != nil {
		t.Fatalf("read after AAD migration: %v", err)
	}
	if got.Secret != "legacy-secret" {
		t.Fatalf("plaintext not preserved through migration: %q", got.Secret)
	}
}

// TestResealWrongPreviousKeyAborts: re-sealing with the wrong previous key opens
// nothing and commits nothing (fail-closed, all-or-nothing).
func TestResealWrongPreviousKeyAborts(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	realOld := cipherWithKey(t, 0x04)
	wrongOld := cipherWithKey(t, 0x44)
	newC := cipherWithKey(t, 0x05)

	if err := credVaultWith(t, db, realOld).SetBankCredential(ctx, "tnt", "c6", "cid", "s"); err != nil {
		t.Fatalf("set: %v", err)
	}
	newV := credVaultWith(t, db, newC)
	if _, err := newV.Reseal(ctx, wrongOld); err == nil {
		t.Fatal("reseal with the wrong previous key must fail")
	}
	// Nothing committed: the row still opens with the real old key.
	if _, err := credVaultWith(t, db, realOld).GetBankCredential(ctx, "tnt", "c6"); err != nil {
		t.Fatalf("row must be unchanged after aborted reseal: %v", err)
	}
}

// TestResealClosedDBErrors: a closed database surfaces an error from both Reseal
// paths (the begin/scan branch), and never panics.
func TestResealClosedDBErrors(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	old := cipherWithKey(t, 0x21)
	credV := credVaultWith(t, db, cipherWithKey(t, 0x22))
	certV := certVaultWith(t, db, cipherWithKey(t, 0x22))
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := credV.Reseal(ctx, old); err == nil {
		t.Fatal("credential reseal on closed db must error")
	}
	if _, err := certV.Reseal(ctx, old); err == nil {
		t.Fatal("certificate reseal on closed db must error")
	}
}

// TestResealCertificateKEK: the certificate private key survives a KEK rotation
// (only its encryption changes; the public metadata is unaffected).
func TestResealCertificateKEK(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	oldC := cipherWithKey(t, 0x06)
	newC := cipherWithKey(t, 0x07)
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, keyPEM := genCertKeyPEM(t, "payment.verz.example", nb, nb.Add(365*24*time.Hour))

	if err := certVaultWith(t, db, oldC).SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "tnt", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set cert: %v", err)
	}
	newV := certVaultWith(t, db, newC)
	n, err := newV.Reseal(ctx, oldC)
	if err != nil {
		t.Fatalf("reseal cert: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 cert resealed, got %d", n)
	}
	meta, err := newV.GetBankCertificateMeta(ctx, "tnt", "c6")
	if err != nil {
		t.Fatalf("meta after reseal: %v", err)
	}
	if meta.SubjectCN != "payment.verz.example" {
		t.Fatalf("CN mismatch after reseal: %q", meta.SubjectCN)
	}
}

// TestResealNilPreviousCipher: a nil previous cipher is rejected (fail-closed).
func TestResealNilPreviousCipher(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	if _, err := newCredentialVault(t, db).Reseal(ctx, nil); err == nil {
		t.Fatal("nil previous cipher must be rejected")
	}
	if _, err := newCertificateVault(t, db).Reseal(ctx, nil); err == nil {
		t.Fatal("nil previous cipher must be rejected (cert)")
	}
}

// TestResealAllRotatesBothTables: the happy path rotates credentials AND
// certificates together to the new KEK; afterwards both open with the new cipher and
// no longer with the old one, and the returned counts reflect both tables.
func TestResealAllRotatesBothTables(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	oldC := cipherWithKey(t, 0x08)
	newC := cipherWithKey(t, 0x09)
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, keyPEM := genCertKeyPEM(t, "payment.verz.example", nb, nb.Add(365*24*time.Hour))

	if err := credVaultWith(t, db, oldC).SetBankCredential(ctx, "tnt", "c6", "cid", "the-secret"); err != nil {
		t.Fatalf("set cred: %v", err)
	}
	if err := certVaultWith(t, db, oldC).SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "tnt", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set cert: %v", err)
	}

	credV := credVaultWith(t, db, newC)
	certV := certVaultWith(t, db, newC)
	credN, certN, err := postgres.ResealAll(ctx, credV, certV, oldC)
	if err != nil {
		t.Fatalf("reseal all: %v", err)
	}
	if credN != 1 || certN != 1 {
		t.Fatalf("want 1 cred + 1 cert resealed, got %d + %d", credN, certN)
	}

	got, err := credV.GetBankCredential(ctx, "tnt", "c6")
	if err != nil || got.Secret != "the-secret" {
		t.Fatalf("credential not preserved under new key: %+v err=%v", got, err)
	}
	if _, err := certV.GetBankCertificateMeta(ctx, "tnt", "c6"); err != nil {
		t.Fatalf("certificate not readable under new key: %v", err)
	}
	// The old cipher must no longer open either table.
	if _, err := credVaultWith(t, db, oldC).GetBankCredential(ctx, "tnt", "c6"); err == nil {
		t.Fatal("old key must not open credentials after ResealAll")
	}
}

// TestResealAllCertFailureRollsBackCredentials is the SIN-69372 acceptance criterion:
// when the certificate rewrite fails AFTER the credential rewrite has been staged in
// the shared transaction, NOTHING is committed — the credential row still opens with
// the OLD key. This proves the two tables rotate all-or-nothing and the tool can be
// retried with the same (new, previous) pair instead of leaving a half-rotated vault.
func TestResealAllCertFailureRollsBackCredentials(t *testing.T) {
	t.Parallel()
	dsn, db := openVaultDB(t)
	ctx := context.Background()
	oldC := cipherWithKey(t, 0x0A)
	newC := cipherWithKey(t, 0x0B)
	wrongC := cipherWithKey(t, 0xAB) // seals the cert key with a key ResealAll cannot open

	// A credential row that ResealAll CAN open (sealed with the real old key).
	if err := credVaultWith(t, db, oldC).SetBankCredential(ctx, "tnt", "c6", "cid", "keep-me"); err != nil {
		t.Fatalf("set cred: %v", err)
	}

	// A certificate row whose sealed private key is sealed with the WRONG key, so the
	// certificate leg of ResealAll fails its openForReseal — after the credential leg
	// has already staged its UPDATE in the shared transaction.
	poison, err := wrongC.SealWithAAD([]byte("bad-key-pem"), secret.RowAAD("tnt", "c6"))
	if err != nil {
		t.Fatalf("seal poison: %v", err)
	}
	rdb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	if _, err := rdb.ExecContext(ctx,
		`INSERT INTO bank_certificates (tenant_id, bank_id, cert_pem, key_pem_sealed, updated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		"tnt", "c6", "public-cert-pem", poison, "2023-11-14T22:13:20Z"); err != nil {
		t.Fatalf("raw insert poisoned cert: %v", err)
	}

	credV := credVaultWith(t, db, newC)
	certV := certVaultWith(t, db, newC)
	if _, _, err := postgres.ResealAll(ctx, credV, certV, oldC); err == nil {
		t.Fatal("ResealAll must fail when the certificate leg cannot open its blob")
	}

	// The credential row must be UNCHANGED: it still opens with the OLD key, proving
	// the staged credential UPDATE was rolled back with the failed certificate leg.
	got, err := credVaultWith(t, db, oldC).GetBankCredential(ctx, "tnt", "c6")
	if err != nil {
		t.Fatalf("credential must be unchanged after aborted ResealAll (old key must still open): %v", err)
	}
	if got.Secret != "keep-me" {
		t.Fatalf("credential plaintext changed: %q", got.Secret)
	}
	// And it must NOT open with the new key (never partially rotated).
	if _, err := credVaultWith(t, db, newC).GetBankCredential(ctx, "tnt", "c6"); err == nil {
		t.Fatal("credential must not open with the new key after an aborted ResealAll")
	}
}

// TestResealAllRejectsMismatchedDBs: the two vaults must share one *sql.DB, else the
// rotation cannot be atomic — a mismatch is rejected fail-closed before any write.
func TestResealAllRejectsMismatchedDBs(t *testing.T) {
	t.Parallel()
	_, db1 := openVaultDB(t)
	_, db2 := openVaultDB(t)
	ctx := context.Background()
	c := cipherWithKey(t, 0x0C)
	credV := credVaultWith(t, db1, c)
	certV := certVaultWith(t, db2, c)
	if _, _, err := postgres.ResealAll(ctx, credV, certV, cipherWithKey(t, 0x0D)); err == nil {
		t.Fatal("ResealAll with vaults on different DB handles must be rejected")
	}
}

// TestResealAllNilArgs: nil previous cipher and nil vaults are rejected (fail-closed).
func TestResealAllNilArgs(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	credV := newCredentialVault(t, db)
	certV := newCertificateVault(t, db)
	if _, _, err := postgres.ResealAll(ctx, credV, certV, nil); err == nil {
		t.Fatal("nil previous cipher must be rejected")
	}
	if _, _, err := postgres.ResealAll(ctx, nil, certV, cipherWithKey(t, 0x0E)); err == nil {
		t.Fatal("nil credential vault must be rejected")
	}
	if _, _, err := postgres.ResealAll(ctx, credV, nil, cipherWithKey(t, 0x0E)); err == nil {
		t.Fatal("nil certificate vault must be rejected")
	}
}
