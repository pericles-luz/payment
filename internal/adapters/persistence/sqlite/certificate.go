package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/bankcert"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// CertificateVault is the durable, ENCRYPTED-AT-REST implementation of the mTLS
// certificate ports over the bank_certificates table (migration 0012). It satisfies
// the SAME ports as the in-memory secret.CertStore —
// ports.BankCertificateWriter, ports.BankCertificateReader and
// ports.BankCertificateDeleter — so cmd wiring swaps one for the other transparently
// (SIN-69366, umbrella SIN-69118). A certificate written here SURVIVES a restart.
//
// SECURITY (threat C1/C4, ADR-0007): the private key is sealed with secret.Seal
// (AES-256-GCM) before it touches a column, so the durable bytes are ciphertext. It
// is WRITE-ONLY — the read path (GetBankCertificateMeta) returns ONLY public metadata
// re-derived from the stored public leaf certificate; the sealed key is never opened
// on a read, preserving the CertStore posture. The leaf certificate itself is public,
// so cert_pem is stored in plaintext (needed to re-derive metadata on read).
type CertificateVault struct {
	db     *sql.DB
	cipher *secret.Cipher
	clock  ports.Clock
}

// NewCertificateVault wraps a database handle with the sealing cipher and a clock.
// The cipher MUST be non-nil (fail-closed at wiring: a vault that cannot encrypt the
// private key must not exist).
func NewCertificateVault(db *sql.DB, cipher *secret.Cipher, clock ports.Clock) *CertificateVault {
	return &CertificateVault{db: db, cipher: cipher, clock: clock}
}

// Compile-time checks that the adapter satisfies every port the in-memory CertStore does.
var (
	_ ports.BankCertificateWriter  = (*CertificateVault)(nil)
	_ ports.BankCertificateReader  = (*CertificateVault)(nil)
	_ ports.BankCertificateDeleter = (*CertificateVault)(nil)
)

// SetBankCertificate persists the cert/key for (cert.TenantID, cert.BankID). The
// material has already been parsed and validated by the use-case (well-formed, not
// expired, key matches); the store re-checks only the non-empty invariants. The
// private key is sealed before it reaches the column and is never logged or returned
// (threat C1/C4). An empty bankID normalises to the default BankIDC6.
func (v *CertificateVault) SetBankCertificate(ctx context.Context, cert ports.BankCertificate) error {
	if cert.TenantID == "" {
		return shared.NewValidationError("tenant_id", "is required")
	}
	if cert.CertPEM == "" {
		return shared.NewValidationError("cert_pem", "is required")
	}
	if cert.KeyPEM == "" {
		return shared.NewValidationError("key_pem", "is required")
	}
	cert.BankID = secret.DefaultBankID(cert.BankID)
	sealedKey, err := v.cipher.Seal([]byte(cert.KeyPEM))
	if err != nil {
		return fmt.Errorf("seal private key: %w", err)
	}
	if _, err := v.db.ExecContext(ctx,
		`INSERT INTO bank_certificates (tenant_id, bank_id, cert_pem, key_pem_sealed, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (tenant_id, bank_id) DO UPDATE SET
		     cert_pem = excluded.cert_pem,
		     key_pem_sealed = excluded.key_pem_sealed,
		     updated_at = excluded.updated_at`,
		cert.TenantID, cert.BankID, cert.CertPEM, sealedKey, v.now()); err != nil {
		return fmt.Errorf("write bank certificate: %w", err)
	}
	return nil
}

// DeleteBankCertificate hard-removes the certificate for the (tenantID, bankID) pair
// (ADR-0012 §5). It is IDEMPOTENT — removing an absent pair returns nil, no
// enumeration oracle (OWASP A01). The row deletion physically removes the sealed
// private key from the durable store — the at-rest analog of the in-memory adapter's
// zeroise-before-delete (threat C1/C4). An empty bankID resolves to BankIDC6.
func (v *CertificateVault) DeleteBankCertificate(ctx context.Context, tenantID, bankID string) error {
	bankID = secret.DefaultBankID(bankID)
	if _, err := v.db.ExecContext(ctx,
		`DELETE FROM bank_certificates WHERE tenant_id = ? AND bank_id = ?`, tenantID, bankID); err != nil {
		return fmt.Errorf("delete bank certificate: %w", err)
	}
	return nil
}

// GetBankCertificateMeta returns ONLY the public metadata of the stored certificate,
// re-derived from the stored leaf via bankcert.ParseCert; the sealed private key is
// NEVER opened here (write-only key). The lookup is exact-match with NO fallback: a
// missing pair returns shared.ErrNotFound and never resolves to another bank or tenant
// (deny-by-default; threat T1/T2). An empty bankID resolves to BankIDC6.
func (v *CertificateVault) GetBankCertificateMeta(ctx context.Context, tenantID, bankID string) (ports.BankCertificateMeta, error) {
	bankID = secret.DefaultBankID(bankID)
	var certPEM string
	err := v.db.QueryRowContext(ctx,
		`SELECT cert_pem FROM bank_certificates WHERE tenant_id = ? AND bank_id = ?`,
		tenantID, bankID).Scan(&certPEM)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.BankCertificateMeta{}, shared.ErrNotFound
	}
	if err != nil {
		return ports.BankCertificateMeta{}, fmt.Errorf("read bank certificate: %w", err)
	}
	meta, err := bankcert.ParseCert(certPEM)
	if err != nil {
		// The material was validated on write, so a parse failure here is an internal
		// inconsistency — surface it rather than silently returning blanks.
		return ports.BankCertificateMeta{}, err
	}
	return ports.BankCertificateMeta{
		TenantID:          tenantID,
		BankID:            bankID,
		SubjectCN:         meta.SubjectCN,
		Issuer:            meta.Issuer,
		SerialNumber:      meta.SerialNumber,
		FingerprintSHA256: meta.FingerprintSHA256,
		NotBefore:         meta.NotBefore,
		NotAfter:          meta.NotAfter,
	}, nil
}

// now returns the current instant formatted as RFC3339-UTC (the adapter-wide layout).
func (v *CertificateVault) now() string {
	return v.clock.Now().UTC().Format(tsLayout)
}
