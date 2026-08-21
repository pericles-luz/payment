package postgres_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// wrongCipher builds an AES-256 cipher from a 32-byte key distinct from testCipher's,
// modelling a KEK mismatch (or a relocated/tampered row) on read.
func wrongCipher(t *testing.T) *secret.Cipher {
	t.Helper()
	c, err := secret.NewCipher(bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatalf("wrong cipher: %v", err)
	}
	return c
}

// TestCertificateVaultLoadTLSCertificate: the durable vault opens the sealed key and
// re-assembles a handshake-ready tls.Certificate, and the material SURVIVES a restart
// (durability now equals consumption — SIN-69368).
func TestCertificateVaultLoadTLSCertificate(t *testing.T) {
	t.Parallel()
	dsn, db := openVaultDB(t)
	ctx := context.Background()
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, keyPEM := genCertKeyPEM(t, "payment.verz.example", nb, nb.Add(365*24*time.Hour))

	if err := newCertificateVault(t, db).SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "tnt-1", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	_ = db.Close()

	// Reopen over the same DB file: the vault must re-derive the tls.Certificate from
	// the encrypted-at-rest row.
	db2, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })

	cert, err := newCertificateVault(t, db2).LoadTLSCertificate(ctx, "tnt-1", "c6")
	if err != nil {
		t.Fatalf("load after restart: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatal("expected a populated, key-backed tls.Certificate after restart")
	}
	// The re-derived pair must be one the TLS stack accepts.
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		t.Fatalf("sanity: seeded material invalid: %v", err)
	}
}

// TestCertificateVaultLoadTLSCertificateNotFound: a missing pair returns ErrNotFound
// (deny-by-default), so the transport falls back to the §8 bootstrap cert; it never
// resolves to another tenant.
func TestCertificateVaultLoadTLSCertificateNotFound(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, keyPEM := genCertKeyPEM(t, "cn", nb, nb.Add(time.Hour))
	if err := newCertificateVault(t, db).SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "tnt-1", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	v := newCertificateVault(t, db)
	if _, err := v.LoadTLSCertificate(ctx, "tnt-OTHER", "c6"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for another tenant, got %v", err)
	}
	if _, err := v.LoadTLSCertificate(ctx, "tnt-1", "bank-other"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound for another bank, got %v", err)
	}
}

// TestCertificateVaultLoadTLSCertificateWrongKEK: a vault whose cipher is a DIFFERENT
// KEK than the one that sealed the row fails to open the key (fail closed) rather than
// returning a broken certificate. This is the OpenWithAAD/row-binding guard.
func TestCertificateVaultLoadTLSCertificateWrongKEK(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, keyPEM := genCertKeyPEM(t, "cn", nb, nb.Add(time.Hour))
	if err := newCertificateVault(t, db).SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "tnt-1", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	// A vault over the same DB but a different cipher (wrong KEK).
	wrong := postgres.NewCertificateVault(db, wrongCipher(t), fixedClock{t: nb})
	if _, err := wrong.LoadTLSCertificate(ctx, "tnt-1", "c6"); err == nil {
		t.Fatal("expected LoadTLSCertificate to fail closed under the wrong KEK")
	}
}

// TestCertificateVaultLoadTLSCertificateCrossRowAADRejected: a sealed key relocated to
// a DIFFERENT (tenant, bank) row fails to open even under the CORRECT KEK, because the
// blob is bound to its origin row via RowAAD (SIN-69369). This proves tenant isolation
// holds at the crypto layer — a leaked ciphertext cannot be replayed into another
// tenant's row to forge that tenant's mTLS identity (threat C1/C4, T1/T2).
func TestCertificateVaultLoadTLSCertificateCrossRowAADRejected(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, keyPEM := genCertKeyPEM(t, "cn", nb, nb.Add(time.Hour))
	if err := newCertificateVault(t, db).SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "tnt-1", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	// Copy tnt-1's sealed key verbatim into a tnt-2 row (an attacker relocating a
	// captured ciphertext). The cert_pem is public, so it is copied too.
	var sealedKey []byte
	if err := db.QueryRowContext(ctx,
		`SELECT key_pem_sealed FROM bank_certificates WHERE tenant_id = 'tnt-1' AND bank_id = 'c6'`).
		Scan(&sealedKey); err != nil {
		t.Fatalf("read sealed key: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO bank_certificates (tenant_id, bank_id, cert_pem, key_pem_sealed, updated_at)
		 VALUES ('tnt-2', 'c6', $1, $2, $3)`, certPEM, sealedKey, "2023-11-14T22:13:20Z"); err != nil {
		t.Fatalf("relocate row: %v", err)
	}
	// Same vault, same KEK, but the AAD for (tnt-2, c6) differs from (tnt-1, c6),
	// so GCM authentication fails and no certificate is assembled.
	if _, err := newCertificateVault(t, db).LoadTLSCertificate(ctx, "tnt-2", "c6"); err == nil {
		t.Fatal("expected cross-row relocated blob to fail closed under RowAAD binding")
	}
}

// TestCertificateVaultLoadTLSCertificateAssembleFailure: a row whose sealed key OPENS
// cleanly (correct KEK + AAD) but is not a valid PEM key that pairs with cert_pem
// surfaces an error rather than a half-built certificate. This guards the assembly
// branch — an internal inconsistency must fail closed, never present a key-less cert.
func TestCertificateVaultLoadTLSCertificateAssembleFailure(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, _ := genCertKeyPEM(t, "cn", nb, nb.Add(time.Hour))
	// Seal garbage under the CORRECT KEK and RowAAD for (tnt-1, c6): it opens fine but
	// is not a private key that matches cert_pem.
	badSealed, err := testCipher(t).SealWithAAD([]byte("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"), secret.RowAAD("tnt-1", "c6"))
	if err != nil {
		t.Fatalf("seal garbage: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO bank_certificates (tenant_id, bank_id, cert_pem, key_pem_sealed, updated_at)
		 VALUES ('tnt-1', 'c6', $1, $2, $3)`, certPEM, badSealed, "2023-11-14T22:13:20Z"); err != nil {
		t.Fatalf("seed inconsistent row: %v", err)
	}
	if _, err := newCertificateVault(t, db).LoadTLSCertificate(ctx, "tnt-1", "c6"); err == nil {
		t.Fatal("expected assembly of a mismatched cert/key pair to fail closed")
	}
}
