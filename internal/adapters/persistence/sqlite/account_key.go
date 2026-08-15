package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/accountkey"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// AccountKeyStore is the durable, hash-at-rest implementation of
// ports.AccountKeyStore over the account_keys table (migration 0011). It satisfies
// the SAME port as the in-memory adapter, so wiring swaps one for the other without
// the use-cases knowing (ADR-0011 §3, SIN-69278/B1).
//
// It is intentionally its own struct with its own *sql.DB rather than a method set
// on Store: an account key is a credential, not a financial aggregate, so it stays
// out of the payment Repository/unit-of-work bundle. Its only multi-statement write
// (rotate) runs in a private transaction for atomicity.
//
// SECURITY (ADR-0011 §3, threat T5): the plaintext secret is never persisted — the
// domain hashes it (accountkey.Mint) before it reaches SQL, and only the hex SHA-256
// is written to key_hash. Authentication is an indexed lookup by that hash over
// active rows, never a plaintext comparison, so there is no per-row timing oracle and
// no secret ever appears in a query argument in the clear.
type AccountKeyStore struct {
	db    *sql.DB
	clock ports.Clock
}

// NewAccountKeyStore wraps a database handle. The clock is injected so mint/rotate
// timestamps stay deterministic in tests (same convention as the other adapters).
func NewAccountKeyStore(db *sql.DB, clock ports.Clock) *AccountKeyStore {
	return &AccountKeyStore{db: db, clock: clock}
}

// Compile-time check that the adapter satisfies the port.
var _ ports.AccountKeyStore = (*AccountKeyStore)(nil)

// PutKey mints a fresh key for accountID and returns the plaintext once. create==rotate:
// in a single transaction it supersedes every currently-active key for the account
// (active=0, rotated_at=now) and inserts the new active row, so the previous secret is
// invalidated atomically and immediately. The plaintext is returned only here.
func (s *AccountKeyStore) PutKey(ctx context.Context, accountID string) (string, error) {
	if accountID == "" {
		return "", shared.NewValidationError("account_id", "account id is required")
	}
	now := s.clock.Now()
	key, plaintext, err := accountkey.Mint(accountID, now)
	if err != nil {
		return "", err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin account-key tx: %w", err)
	}
	// Supersede any prior active key for this account BEFORE inserting the new one,
	// so at most one row per account is ever active (create==rotate invalidation).
	if _, err := tx.ExecContext(ctx,
		`UPDATE account_keys SET active = 0, rotated_at = ? WHERE account_id = ? AND active = 1`,
		now.UTC().Format(tsLayout), accountID); err != nil {
		_ = tx.Rollback()
		return "", fmt.Errorf("supersede account key: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO account_keys (account_id, key_hash, active, created_at, rotated_at)
		 VALUES (?, ?, 1, ?, NULL)`,
		key.AccountID(), key.Hash(), key.CreatedAt().UTC().Format(tsLayout)); err != nil {
		_ = tx.Rollback()
		return "", fmt.Errorf("insert account key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit account key: %w", err)
	}
	return plaintext, nil
}

// Rotate is the explicit rotation name; create==rotate, so it delegates to PutKey.
func (s *AccountKeyStore) Rotate(ctx context.Context, accountID string) (string, error) {
	return s.PutKey(ctx, accountID)
}

// AuthenticateAccountKey resolves a presented plaintext secret to its owning account
// id via an indexed lookup of its hash among active rows. Any miss — unknown,
// malformed, or superseded secret, or a scan error — returns ("", false), a single
// non-oracle failure mode. The secret itself is never sent to the database; only its
// hash is (threat T5).
func (s *AccountKeyStore) AuthenticateAccountKey(ctx context.Context, secret string) (string, bool) {
	if secret == "" {
		return "", false
	}
	hash := accountkey.HashSecret(secret)
	var accountID string
	err := s.db.QueryRowContext(ctx,
		`SELECT account_id FROM account_keys WHERE key_hash = ? AND active = 1`, hash).Scan(&accountID)
	if err != nil {
		// ErrNoRows (unknown/rotated secret) and any other read error both fail closed
		// and indistinguishably — no oracle about which keys exist, and we NEVER fail
		// open on an infrastructure error.
		return "", false
	}
	return accountID, true
}
