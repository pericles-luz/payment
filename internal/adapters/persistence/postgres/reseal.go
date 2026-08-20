package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
)

// openForReseal decrypts a blob written by a previous cipher, transparently
// upgrading legacy blobs. It first tries the AAD-bound Open (the row is bound to
// its (tenant, bank), the posture since SIN-69369); if that fails it retries with
// no AAD, which recovers blobs written before row-binding existed (pre-SIN-69369,
// sealed with a nil AAD). Both failing means the blob cannot be recovered with
// oldCipher — a wrong PAYMENT_BANK_VAULT_KEY_PREVIOUS or a corrupted row — and the
// error aborts the whole re-seal so nothing is half-rotated. This fallback lives
// ONLY in the offline re-seal path, never on the hot read path, so a genuine
// authentication failure at runtime is still fatal.
func openForReseal(oldCipher *secret.Cipher, sealed, aad []byte) ([]byte, error) {
	pt, err := oldCipher.OpenWithAAD(sealed, aad)
	if err == nil {
		return pt, nil
	}
	legacy, legacyErr := oldCipher.OpenWithAAD(sealed, nil)
	if legacyErr == nil {
		return legacy, nil
	}
	// Report the AAD-bound failure (the expected path); the legacy attempt was a
	// best-effort upgrade. Never include the blob or key material.
	return nil, fmt.Errorf("reseal: cannot open blob with previous key: %w", err)
}

// ResealAll re-encrypts BOTH the bank_credentials and bank_certificates tables from
// oldCipher to the new cipher inside a SINGLE transaction, so the two tables rotate
// all-or-nothing (SIN-69372). If the certificate rewrite fails after the credential
// rewrite has already been staged, the shared transaction is rolled back and NEITHER
// table is committed — the vault stays fully readable with the OLD key (fail-closed,
// reversible), and the operator can simply retry with the same (new, previous) pair.
//
// This is the path the vault-reseal command uses. The two vaults MUST share the same
// *sql.DB (they do when wired from one handle in cmd/vault-reseal); a mismatch is a
// wiring bug and is rejected fail-closed rather than silently splitting the rotation
// back into two transactions. Returns the rows rewritten in each table.
func ResealAll(ctx context.Context, cred *CredentialVault, cert *CertificateVault, oldCipher *secret.Cipher) (credN, certN int, err error) {
	if oldCipher == nil {
		return 0, 0, fmt.Errorf("reseal: previous cipher is required")
	}
	if cred == nil || cert == nil {
		return 0, 0, fmt.Errorf("reseal: both credential and certificate vaults are required")
	}
	if cred.db != cert.db {
		return 0, 0, fmt.Errorf("reseal: credential and certificate vaults must share one database handle for atomic rotation")
	}

	tx, err := cred.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("reseal: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	credN, err = cred.resealCredentialsTx(ctx, tx, oldCipher)
	if err != nil {
		return 0, 0, err
	}
	certN, err = cert.resealCertificatesTx(ctx, tx, oldCipher)
	if err != nil {
		return 0, 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("reseal: commit: %w", err)
	}
	return credN, certN, nil
}

// Reseal re-encrypts every bank_credentials row from oldCipher to this vault's own
// cipher, preserving the plaintext, in ONE transaction: on any error nothing is
// committed, so a failed rotation leaves the vault fully readable with the OLD key
// (fail-closed, reversible). It rotates only the credential table; to rotate the
// credential and certificate tables atomically together use ResealAll. Returns the
// number of rows rewritten.
//
// Operationally: set PAYMENT_BANK_VAULT_KEY to the NEW key and
// PAYMENT_BANK_VAULT_KEY_PREVIOUS to the CURRENT key, then run the re-seal command
// (see docs/ops/bank-vault-kek-rotation-runbook.md). Running it twice with the same
// pair fails loudly (the second pass cannot open new-key blobs with the old key)
// rather than corrupting data.
func (v *CredentialVault) Reseal(ctx context.Context, oldCipher *secret.Cipher) (int, error) {
	if oldCipher == nil {
		return 0, fmt.Errorf("reseal: previous cipher is required")
	}
	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("reseal credentials: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	n, err := v.resealCredentialsTx(ctx, tx, oldCipher)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("reseal credentials: commit: %w", err)
	}
	return n, nil
}

// resealCredentialsTx rewrites every bank_credentials row within the caller's
// transaction, opening each sealed column with oldCipher (via openForReseal, so
// pre-row-binding blobs are upgraded) and re-sealing with the current cipher, bound
// to the row's RowAAD(tenant, bank). It never begins, commits, or rolls back tx —
// the caller owns the transaction lifecycle so this rewrite can share one atomic
// transaction with the certificate rewrite. Returns the number of rows rewritten.
func (v *CredentialVault) resealCredentialsTx(ctx context.Context, tx *sql.Tx, oldCipher *secret.Cipher) (int, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT tenant_id, bank_id, secret_sealed, creditor_key_sealed FROM bank_credentials`)
	if err != nil {
		return 0, fmt.Errorf("reseal credentials: scan: %w", err)
	}
	type row struct {
		tenantID, bankID    string
		secSealed, ckSealed []byte
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.tenantID, &r.bankID, &r.secSealed, &r.ckSealed); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("reseal credentials: read row: %w", err)
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("reseal credentials: rows: %w", err)
	}
	_ = rows.Close()

	n := 0
	for _, r := range batch {
		aad := secret.RowAAD(r.tenantID, r.bankID)
		sec, err := openForReseal(oldCipher, r.secSealed, aad)
		if err != nil {
			return 0, err
		}
		newSec, err := v.cipher.SealWithAAD(sec, aad)
		if err != nil {
			return 0, fmt.Errorf("reseal credentials: seal secret: %w", err)
		}
		var newCK []byte
		if len(r.ckSealed) > 0 {
			ck, err := openForReseal(oldCipher, r.ckSealed, aad)
			if err != nil {
				return 0, err
			}
			if newCK, err = v.cipher.SealWithAAD(ck, aad); err != nil {
				return 0, fmt.Errorf("reseal credentials: seal creditor key: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE bank_credentials SET secret_sealed = $1, creditor_key_sealed = $2 WHERE tenant_id = $3 AND bank_id = $4`,
			newSec, newCK, r.tenantID, r.bankID); err != nil {
			return 0, fmt.Errorf("reseal credentials: write row: %w", err)
		}
		n++
	}
	return n, nil
}

// Reseal re-encrypts every bank_certificates row's sealed private key from
// oldCipher to this vault's own cipher (see CredentialVault.Reseal for the full
// contract) in ONE transaction. cert_pem is public and left untouched. To rotate the
// certificate and credential tables atomically together use ResealAll. Returns the
// rows rewritten.
func (v *CertificateVault) Reseal(ctx context.Context, oldCipher *secret.Cipher) (int, error) {
	if oldCipher == nil {
		return 0, fmt.Errorf("reseal: previous cipher is required")
	}
	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("reseal certificates: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	n, err := v.resealCertificatesTx(ctx, tx, oldCipher)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("reseal certificates: commit: %w", err)
	}
	return n, nil
}

// resealCertificatesTx rewrites every bank_certificates row's sealed private key
// within the caller's transaction. Like resealCredentialsTx it never begins, commits,
// or rolls back tx — the caller owns the lifecycle so both tables can share one atomic
// transaction. Returns the number of rows rewritten.
func (v *CertificateVault) resealCertificatesTx(ctx context.Context, tx *sql.Tx, oldCipher *secret.Cipher) (int, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT tenant_id, bank_id, key_pem_sealed FROM bank_certificates`)
	if err != nil {
		return 0, fmt.Errorf("reseal certificates: scan: %w", err)
	}
	type row struct {
		tenantID, bankID string
		keySealed        []byte
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.tenantID, &r.bankID, &r.keySealed); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("reseal certificates: read row: %w", err)
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("reseal certificates: rows: %w", err)
	}
	_ = rows.Close()

	n := 0
	for _, r := range batch {
		aad := secret.RowAAD(r.tenantID, r.bankID)
		key, err := openForReseal(oldCipher, r.keySealed, aad)
		if err != nil {
			return 0, err
		}
		newKey, err := v.cipher.SealWithAAD(key, aad)
		if err != nil {
			return 0, fmt.Errorf("reseal certificates: seal key: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE bank_certificates SET key_pem_sealed = $1 WHERE tenant_id = $2 AND bank_id = $3`,
			newKey, r.tenantID, r.bankID); err != nil {
			return 0, fmt.Errorf("reseal certificates: write row: %w", err)
		}
		n++
	}
	return n, nil
}
