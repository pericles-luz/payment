package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// genCertKeyPEM builds a self-signed leaf certificate and its matching EC private
// key, PEM-encoded (mirrors the bankcert test helper). EC P-256 keeps generation
// fast.
func genCertKeyPEM(t *testing.T, cn string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func newCertificateVault(t *testing.T, db *sql.DB) *postgres.CertificateVault {
	t.Helper()
	return postgres.NewCertificateVault(db, testCipher(t), fixedClock{t: time.Unix(1700000000, 0).UTC()})
}

// TestCertificateVaultRoundTripSurvivesRestart: a certificate written via the port is
// readable (its public metadata) after the store is recreated over the same DB file.
func TestCertificateVaultRoundTripSurvivesRestart(t *testing.T) {
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

	db2, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	meta, err := newCertificateVault(t, db2).GetBankCertificateMeta(ctx, "tnt-1", "c6")
	if err != nil {
		t.Fatalf("get meta after restart: %v", err)
	}
	if meta.SubjectCN != "payment.verz.example" {
		t.Fatalf("CN mismatch after restart: %q", meta.SubjectCN)
	}
	if meta.TenantID != "tnt-1" || meta.BankID != "c6" {
		t.Fatalf("identity mismatch: %+v", meta)
	}
	if meta.NotAfter.IsZero() {
		t.Fatal("NotAfter not derived from stored cert")
	}
}

// TestCertificateVaultKeyEncryptedAtRest: the private key is ciphertext at rest and is
// NEVER surfaced by the read path (the reader returns only public metadata; the vault
// exposes no method that returns KeyPEM — write-only by construction).
func TestCertificateVaultKeyEncryptedAtRest(t *testing.T) {
	t.Parallel()
	dsn, db := openVaultDB(t)
	ctx := context.Background()
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, keyPEM := genCertKeyPEM(t, "cn", nb, nb.Add(time.Hour))
	if err := newCertificateVault(t, db).SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "tnt-1", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}

	rdb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer func() { _ = rdb.Close() }()
	var keySealed []byte
	var storedCertPEM string
	if err := rdb.QueryRowContext(ctx,
		`SELECT key_pem_sealed, cert_pem FROM bank_certificates WHERE tenant_id = $1 AND bank_id = $2`,
		"tnt-1", "c6").Scan(&keySealed, &storedCertPEM); err != nil {
		t.Fatalf("raw read: %v", err)
	}
	// The private key never appears in cleartext at rest.
	if bytes.Contains(keySealed, []byte("PRIVATE KEY")) || bytes.Contains(keySealed, []byte(keyPEM)) {
		t.Fatal("private key stored in plaintext at rest")
	}
	// The public leaf certificate is stored as-is (it is public; needed to re-derive meta).
	if storedCertPEM != certPEM {
		t.Fatal("public cert not stored verbatim")
	}
}

// TestCertificateVaultCorruptCertSurfaces: a row whose cert_pem is not a parseable
// certificate is an internal inconsistency (the material is validated on write). The
// reader surfaces the parse error rather than silently returning blank metadata.
func TestCertificateVaultCorruptCertSurfaces(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	// Insert a malformed row directly (bypassing the validating writer).
	if _, err := db.ExecContext(ctx,
		`INSERT INTO bank_certificates (tenant_id, bank_id, cert_pem, key_pem_sealed, updated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		"tnt-1", "c6", "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----", []byte("x"), "2023-11-14T00:00:00Z"); err != nil {
		t.Fatalf("raw insert: %v", err)
	}
	_, err := newCertificateVault(t, db).GetBankCertificateMeta(ctx, "tnt-1", "c6")
	if err == nil {
		t.Fatal("corrupt cert_pem must surface a parse error, not blank meta")
	}
	if errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("corrupt row must not masquerade as NotFound: %v", err)
	}
}

// TestCertificateVaultGetNotFound: exact-match, no fallback across tenant/bank.
func TestCertificateVaultGetNotFound(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCertificateVault(t, db)
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, keyPEM := genCertKeyPEM(t, "cn", nb, nb.Add(time.Hour))
	if err := v.SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "tnt-1", BankID: "c6", CertPEM: certPEM, KeyPEM: keyPEM,
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	for _, c := range []struct{ tenant, bank string }{{"tnt-2", "c6"}, {"tnt-1", "other"}} {
		if _, err := v.GetBankCertificateMeta(ctx, c.tenant, c.bank); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("(%s,%s): want ErrNotFound, got %v", c.tenant, c.bank, err)
		}
	}
}

// TestCertificateVaultSetValidation: empty tenant/cert/key are rejected.
func TestCertificateVaultSetValidation(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCertificateVault(t, db)
	var ve *shared.ValidationError
	cases := []struct {
		name string
		cert ports.BankCertificate
	}{
		{"empty tenant", ports.BankCertificate{CertPEM: "c", KeyPEM: "k"}},
		{"empty cert", ports.BankCertificate{TenantID: "t", KeyPEM: "k"}},
		{"empty key", ports.BankCertificate{TenantID: "t", CertPEM: "c"}},
	}
	for _, c := range cases {
		if err := v.SetBankCertificate(ctx, c.cert); !errors.As(err, &ve) {
			t.Fatalf("%s: want ValidationError, got %v", c.name, err)
		}
	}
}

// TestCertificateVaultDeleteIdempotent: absent delete is a no-op; present delete
// removes the row (GetMeta → NotFound); re-delete stays a no-op.
func TestCertificateVaultDeleteIdempotent(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCertificateVault(t, db)
	nb := time.Unix(1700000000, 0).UTC()
	certPEM, keyPEM := genCertKeyPEM(t, "cn", nb, nb.Add(time.Hour))

	if err := v.DeleteBankCertificate(ctx, "ghost", "c6"); err != nil {
		t.Fatalf("delete absent: %v", err)
	}
	if err := v.SetBankCertificate(ctx, ports.BankCertificate{
		TenantID: "tnt-1", BankID: "", CertPEM: certPEM, KeyPEM: keyPEM, // empty bank → c6
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := v.DeleteBankCertificate(ctx, "tnt-1", "c6"); err != nil {
		t.Fatalf("delete present: %v", err)
	}
	if _, err := v.GetBankCertificateMeta(ctx, "tnt-1", "c6"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
	if err := v.DeleteBankCertificate(ctx, "tnt-1", "c6"); err != nil {
		t.Fatalf("delete again: %v", err)
	}
}

// TestCertificateVaultOverwrite: re-setting the same (tenant,bank) replaces the cert.
func TestCertificateVaultOverwrite(t *testing.T) {
	t.Parallel()
	_, db := openVaultDB(t)
	ctx := context.Background()
	v := newCertificateVault(t, db)
	nb := time.Unix(1700000000, 0).UTC()
	c1, k1 := genCertKeyPEM(t, "first.example", nb, nb.Add(time.Hour))
	c2, k2 := genCertKeyPEM(t, "second.example", nb, nb.Add(time.Hour))
	if err := v.SetBankCertificate(ctx, ports.BankCertificate{TenantID: "t", BankID: "c6", CertPEM: c1, KeyPEM: k1}); err != nil {
		t.Fatalf("set 1: %v", err)
	}
	if err := v.SetBankCertificate(ctx, ports.BankCertificate{TenantID: "t", BankID: "c6", CertPEM: c2, KeyPEM: k2}); err != nil {
		t.Fatalf("set 2: %v", err)
	}
	meta, err := v.GetBankCertificateMeta(ctx, "t", "c6")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if meta.SubjectCN != "second.example" {
		t.Fatalf("overwrite failed: %q", meta.SubjectCN)
	}
}
