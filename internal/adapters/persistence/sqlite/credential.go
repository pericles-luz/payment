package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// CredentialVault is the durable, ENCRYPTED-AT-REST implementation of the bank
// OAuth-credential ports over the bank_credentials table (migration 0012). It
// satisfies the SAME ports as the in-memory secret.Store —
// ports.CredentialStore (read), ports.CredentialWriter, ports.CredentialDeleter and
// ports.CreditorKeyWriter — so cmd wiring swaps one for the other and the use-cases
// never know (SIN-69366, umbrella SIN-69118). Unlike the in-memory store, a
// credential written here SURVIVES a process restart, which is the go-live
// requirement the CEO surfaced: a runtime-configured C6 credential must outlive a
// redeploy.
//
// SECURITY (threat C1/C4, ADR-0007): the OAuth secret and the routing-sensitive PIX
// creditor key are sealed with secret.Seal (AES-256-GCM) BEFORE they touch a column,
// so the durable bytes are ciphertext, never plaintext. The AES key is a KEK loaded
// from env; it is held only in the injected *secret.Cipher. The client_id is an
// identifier (not a secret) and stays plaintext, matching how the domain logs it.
type CredentialVault struct {
	db     *sql.DB
	cipher *secret.Cipher
	clock  ports.Clock
}

// NewCredentialVault wraps a database handle with the sealing cipher and a clock
// (injected so updated_at stays deterministic in tests). The cipher MUST be non-nil:
// a vault that cannot encrypt must not exist (fail-closed at wiring).
func NewCredentialVault(db *sql.DB, cipher *secret.Cipher, clock ports.Clock) *CredentialVault {
	return &CredentialVault{db: db, cipher: cipher, clock: clock}
}

// Compile-time checks that the adapter satisfies every port the in-memory Store does.
var (
	_ ports.CredentialStore      = (*CredentialVault)(nil)
	_ ports.CredentialWriter     = (*CredentialVault)(nil)
	_ ports.CredentialDeleter    = (*CredentialVault)(nil)
	_ ports.CreditorKeyWriter    = (*CredentialVault)(nil)
	_ ports.CredentialEnumerator = (*CredentialVault)(nil)
)

// Seed inserts each env-provided credential ONLY when its (tenant, bank) row is
// absent — env-as-bootstrap, DB-as-durable-source (SIN-69366 acceptance criterion).
// A fresh deployment is seeded once from PAYMENT_BANK_CREDS; on every later boot a
// row already configured at runtime is left untouched, so an env value never silently
// overwrites a client's runtime change. The map is keyed exactly like
// secret.NewStore: an empty TenantID takes the map key, an empty BankID normalises to
// BankIDC6. Both the secret and the creditor key are sealed before insert.
func (v *CredentialVault) Seed(ctx context.Context, creds map[string]ports.BankCredential) error {
	for k, c := range creds {
		if c.TenantID == "" {
			c.TenantID = k
		}
		c.BankID = secret.DefaultBankID(c.BankID)
		if c.ClientID == "" || c.Secret == "" {
			// A bare/incomplete env entry (e.g. a creditor-key-only row) is not a
			// bootstrappable credential; skip it rather than persist a half-row.
			continue
		}
		aad := secret.RowAAD(c.TenantID, c.BankID)
		sealedSecret, err := v.cipher.SealWithAAD([]byte(c.Secret), aad)
		if err != nil {
			return fmt.Errorf("seal seed secret: %w", err)
		}
		var sealedCK []byte
		if c.CreditorKey != "" {
			if sealedCK, err = v.cipher.SealWithAAD([]byte(c.CreditorKey), aad); err != nil {
				return fmt.Errorf("seal seed creditor key: %w", err)
			}
		}
		if _, err := v.db.ExecContext(ctx,
			`INSERT INTO bank_credentials (tenant_id, bank_id, client_id, secret_sealed, creditor_key_sealed, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (tenant_id, bank_id) DO NOTHING`,
			c.TenantID, c.BankID, c.ClientID, sealedSecret, sealedCK, v.now()); err != nil {
			return fmt.Errorf("seed bank credential: %w", err)
		}
	}
	return nil
}

// GetBankCredential resolves the credential for the EXACT (tenantID, bankID) pair
// with NO fallback: a missing pair returns shared.ErrNotFound and never resolves to
// another bank or tenant (deny-by-default; threat T1/T2). An empty bankID resolves to
// the default BankIDC6 (retro-compat). The sealed secret and creditor key are opened
// (decrypted) transiently for the return value and never logged.
func (v *CredentialVault) GetBankCredential(ctx context.Context, tenantID, bankID string) (ports.BankCredential, error) {
	bankID = secret.DefaultBankID(bankID)
	var (
		clientID  string
		sealedSec []byte
		sealedCK  []byte
	)
	err := v.db.QueryRowContext(ctx,
		`SELECT client_id, secret_sealed, creditor_key_sealed FROM bank_credentials WHERE tenant_id = ? AND bank_id = ?`,
		tenantID, bankID).Scan(&clientID, &sealedSec, &sealedCK)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.BankCredential{}, shared.ErrNotFound
	}
	if err != nil {
		return ports.BankCredential{}, fmt.Errorf("read bank credential: %w", err)
	}
	aad := secret.RowAAD(tenantID, bankID)
	sec, err := v.cipher.OpenWithAAD(sealedSec, aad)
	if err != nil {
		return ports.BankCredential{}, fmt.Errorf("open bank secret: %w", err)
	}
	cred := ports.BankCredential{
		TenantID: tenantID,
		BankID:   bankID,
		ClientID: clientID,
		Secret:   string(sec),
	}
	if len(sealedCK) > 0 {
		ck, err := v.cipher.OpenWithAAD(sealedCK, aad)
		if err != nil {
			return ports.BankCredential{}, fmt.Errorf("open creditor key: %w", err)
		}
		cred.CreditorKey = string(ck)
	}
	return cred, nil
}

// SetBankCredential persists the credential for the (tenantID, bankID) pair. Like the
// in-memory Store it is read-modify-write: it PRESERVES any creditor_key already
// registered for the pair, so rotating the client secret never wipes the fund-routing
// key (SIN-66092). Empty inputs are rejected as validation errors WITHOUT echoing the
// secret. The secret is sealed before it reaches the column (never plaintext at rest).
func (v *CredentialVault) SetBankCredential(ctx context.Context, tenantID, bankID, clientID, secretVal string) error {
	if tenantID == "" {
		return shared.NewValidationError("tenant_id", "is required")
	}
	if clientID == "" {
		return shared.NewValidationError("client_id", "is required")
	}
	if secretVal == "" {
		return shared.NewValidationError("secret", "is required")
	}
	bankID = secret.DefaultBankID(bankID)
	sealed, err := v.cipher.SealWithAAD([]byte(secretVal), secret.RowAAD(tenantID, bankID))
	if err != nil {
		return fmt.Errorf("seal bank secret: %w", err)
	}
	// UPSERT preserving creditor_key_sealed: on conflict update only the identity +
	// secret columns, leaving the existing creditor key intact (the two admin writers
	// never clobber each other's field, mirroring the in-memory RMW under s.mu).
	if _, err := v.db.ExecContext(ctx,
		`INSERT INTO bank_credentials (tenant_id, bank_id, client_id, secret_sealed, creditor_key_sealed, updated_at)
		 VALUES (?, ?, ?, ?, NULL, ?)
		 ON CONFLICT (tenant_id, bank_id) DO UPDATE SET
		     client_id = excluded.client_id,
		     secret_sealed = excluded.secret_sealed,
		     updated_at = excluded.updated_at`,
		tenantID, bankID, clientID, sealed, v.now()); err != nil {
		return fmt.Errorf("write bank credential: %w", err)
	}
	return nil
}

// DeleteBankCredential hard-removes the credential for the (tenantID, bankID) pair
// (ADR-0012 §5). It is IDEMPOTENT — removing an absent pair returns nil, giving the
// caller no enumeration oracle (OWASP A01). The row deletion physically removes the
// sealed secret and creditor-key bytes from the durable store — the at-rest analog of
// the in-memory adapter's zeroise-before-delete (threat C1/C4). An empty bankID
// resolves to the default BankIDC6 (retro-compat).
func (v *CredentialVault) DeleteBankCredential(ctx context.Context, tenantID, bankID string) error {
	bankID = secret.DefaultBankID(bankID)
	if _, err := v.db.ExecContext(ctx,
		`DELETE FROM bank_credentials WHERE tenant_id = ? AND bank_id = ?`, tenantID, bankID); err != nil {
		return fmt.Errorf("delete bank credential: %w", err)
	}
	return nil
}

// SetCreditorKey records a tenant's PIX creditor key on the tenant's EXISTING
// default-bank (BankIDC6) credential, read-modify-write so the secret is preserved. A
// tenant with no existing credential is rejected with shared.ErrNotFound (a creditor
// key without a bank identity is meaningless — same guard as the in-memory adapter).
// Empty inputs and a malformed PIX key are rejected as validation errors WITHOUT
// echoing the value. The key is sealed before it reaches the column.
func (v *CredentialVault) SetCreditorKey(ctx context.Context, tenantID, creditorKey string) error {
	if tenantID == "" {
		return shared.NewValidationError("tenant_id", "is required")
	}
	if creditorKey == "" {
		return shared.NewValidationError("creditor_key", "is required")
	}
	if err := secret.ValidateCreditorKey(creditorKey); err != nil {
		return err
	}
	bankID := secret.DefaultBankID("")
	sealed, err := v.cipher.SealWithAAD([]byte(creditorKey), secret.RowAAD(tenantID, bankID))
	if err != nil {
		return fmt.Errorf("seal creditor key: %w", err)
	}
	res, err := v.db.ExecContext(ctx,
		`UPDATE bank_credentials SET creditor_key_sealed = ?, updated_at = ?
		 WHERE tenant_id = ? AND bank_id = ?`,
		sealed, v.now(), tenantID, bankID)
	if err != nil {
		return fmt.Errorf("write creditor key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("creditor key rows affected: %w", err)
	}
	if n == 0 {
		// No bank identity for this tenant — refuse rather than create a half-credential
		// carrying a routing target but no client id/secret.
		return shared.ErrNotFound
	}
	return nil
}

// ListTenantsWithC6Credential returns every tenant_id that has a C6 credential row,
// WITHOUT decrypting or returning any secret — only the non-secret tenant_id column
// is read (SIN-69585 / B2 reconciler enumerator).
func (v *CredentialVault) ListTenantsWithC6Credential(ctx context.Context) ([]string, error) {
	rows, err := v.db.QueryContext(ctx,
		`SELECT tenant_id FROM bank_credentials WHERE bank_id = ?`, ports.BankIDC6)
	if err != nil {
		return nil, fmt.Errorf("list tenants with c6 credential: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan tenant id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenants with c6 credential: %w", err)
	}
	return ids, nil
}

// FindTenantsByCreditorKey implements ports.CreditorKeySharingLookup.
//
// The stored key is SEALED with a per-row AAD, so two rows holding the same key have
// different ciphertexts — comparing columns is impossible by construction. This opens
// each row and compares the plaintext, which costs one AES-GCM open per row with a key
// registered for the bank. That is O(rows) on a path that runs only when someone
// GRAVA uma chave (raro), never on a transaction, so the cost is paid where nobody is
// waiting. The alternative — a stored hash column — would put a brute-forceable
// derivative of a low-entropy secret (CPF, telefone, e-mail) on disk, and this check is
// not worth that.
//
// A row that fails to open is SKIPPED, not fatal: one row sealed under a rotated KEK
// must not block every future key write. It is logged nowhere here (the adapter has no
// logger); the caller sees a shorter list, which fails OPEN for that row — the reason
// the caller must not treat this as an authorisation decision.
func (v *CredentialVault) FindTenantsByCreditorKey(ctx context.Context, bankID, creditorKey string) ([]string, error) {
	bankID = secret.DefaultBankID(bankID)
	if creditorKey == "" {
		return nil, nil
	}
	rows, err := v.db.QueryContext(ctx,
		`SELECT tenant_id, creditor_key_sealed FROM bank_credentials
		 WHERE bank_id = ? AND creditor_key_sealed IS NOT NULL`, bankID)
	if err != nil {
		return nil, fmt.Errorf("list creditor key holders: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var (
			tenantID string
			sealed   []byte
		)
		if err := rows.Scan(&tenantID, &sealed); err != nil {
			return nil, fmt.Errorf("scan creditor key holder: %w", err)
		}
		plain, err := v.cipher.OpenWithAAD(sealed, secret.RowAAD(tenantID, bankID))
		if err != nil {
			continue
		}
		if string(plain) == creditorKey {
			out = append(out, tenantID)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate creditor key holders: %w", err)
	}
	return out, nil
}

// FindTenantsByClientID implements ports.CreditorKeySharingLookup. client_id is an
// identity, not a secret, so it is stored plaintext and compared in SQL.
func (v *CredentialVault) FindTenantsByClientID(ctx context.Context, bankID, clientID string) ([]string, error) {
	bankID = secret.DefaultBankID(bankID)
	if clientID == "" {
		return nil, nil
	}
	rows, err := v.db.QueryContext(ctx,
		`SELECT tenant_id FROM bank_credentials WHERE bank_id = ? AND client_id = ?`, bankID, clientID)
	if err != nil {
		return nil, fmt.Errorf("list client id holders: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, fmt.Errorf("scan client id holder: %w", err)
		}
		out = append(out, tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate client id holders: %w", err)
	}
	return out, nil
}

// now returns the current instant formatted as RFC3339-UTC (the adapter-wide layout).
func (v *CredentialVault) now() string {
	return v.clock.Now().UTC().Format(tsLayout)
}
