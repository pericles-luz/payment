package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	consoleauth "github.com/ia-dev-sindireceita/payment/internal/domain/consoleauth"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// ConsoleCredentialVault is the durable, ENCRYPTED-AT-REST implementation of the
// console-login credential store (SIN-69432, follow-up of SIN-69265). It backs the
// console_credential table (migration 0013) and satisfies the app-layer
// app.ConsoleCredentialStore port — GetCredential/SaveCredential — so cmd wiring
// swaps it in for the in-memory consoleauth.MemStore and the ConsoleAuthService never
// knows. Unlike the in-memory store, a credential provisioned here SURVIVES a process
// restart, which is the go-live requirement the CEO surfaced: after a deploy/CD
// restart the operator must NOT have to re-run /console/bootstrap (caveat SIN-69261).
//
// SECURITY (mirrors the bank secret vault, SIN-69366): the TOTP shared secret is the
// only true secret at rest and is sealed with secret.Seal (AES-256-GCM) BEFORE it
// touches a column, so the durable bytes are ciphertext, never plaintext. The seal is
// bound to the row's username via secret.ConsoleAAD (a copied ciphertext then fails to
// open). The AES key is the SAME KEK as the bank vault (PAYMENT_BANK_VAULT_KEY), held
// only in the injected *secret.Cipher. The password is stored ONLY as its
// argon2id-encoded hash (one-way, safe at rest); the username is a non-secret
// identifier and stays plaintext. Nothing here is ever logged.
type ConsoleCredentialVault struct {
	db     *sql.DB
	cipher *secret.Cipher
	clock  ports.Clock
}

// NewConsoleCredentialVault wraps a database handle with the sealing cipher and a
// clock (injected so updated_at stays deterministic in tests). The cipher MUST be
// non-nil: a store that cannot encrypt the TOTP secret must not exist (fail-closed at
// wiring — the caller only builds this when PAYMENT_BANK_VAULT_KEY is set).
func NewConsoleCredentialVault(db *sql.DB, cipher *secret.Cipher, clock ports.Clock) *ConsoleCredentialVault {
	return &ConsoleCredentialVault{db: db, cipher: cipher, clock: clock}
}

// GetCredential returns the provisioned operator credential, or ok=false when none
// has been set yet (pre-bootstrap). The sealed TOTP secret is opened (decrypted)
// transiently for the return value and never logged. A decrypt failure (tamper /
// wrong key / row relocation) is surfaced as an error so a corrupted credential is
// never silently accepted (fail-closed — Provisioned then treats it as "provisioned"
// and Bootstrap refuses, so the box is never advertised as un-bootstrapped on a
// crypto fault).
func (v *ConsoleCredentialVault) GetCredential(ctx context.Context) (consoleauth.Credential, bool, error) {
	var (
		username   string
		passHash   string
		sealedTOTP []byte
	)
	err := v.db.QueryRowContext(ctx,
		`SELECT username, password_hash, totp_secret_sealed FROM console_credential LIMIT 1`).
		Scan(&username, &passHash, &sealedTOTP)
	if errors.Is(err, sql.ErrNoRows) {
		return consoleauth.Credential{}, false, nil
	}
	if err != nil {
		return consoleauth.Credential{}, false, fmt.Errorf("read console credential: %w", err)
	}
	totp, err := v.cipher.OpenWithAAD(sealedTOTP, secret.ConsoleAAD(username))
	if err != nil {
		return consoleauth.Credential{}, false, fmt.Errorf("open console totp secret: %w", err)
	}
	return consoleauth.RehydrateCredential(username, passHash, string(totp)), true, nil
}

// SaveCredential persists the operator credential. Single-use is enforced at the
// use-case layer (Bootstrap refuses when GetCredential already reports one); this
// adapter just writes whatever it is handed, upserting on the username so a rare
// legitimate re-provision (after an explicit wipe) does not error. The TOTP secret is
// sealed (bound to the username) before it reaches the column — never plaintext at
// rest. The password hash is already one-way and stored as-is.
func (v *ConsoleCredentialVault) SaveCredential(ctx context.Context, c consoleauth.Credential) error {
	sealed, err := v.cipher.SealWithAAD([]byte(c.TOTPSecret()), secret.ConsoleAAD(c.Username()))
	if err != nil {
		return fmt.Errorf("seal console totp secret: %w", err)
	}
	if _, err := v.db.ExecContext(ctx,
		`INSERT INTO console_credential (username, password_hash, totp_secret_sealed, updated_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (username) DO UPDATE SET
		     password_hash = excluded.password_hash,
		     totp_secret_sealed = excluded.totp_secret_sealed,
		     updated_at = excluded.updated_at`,
		c.Username(), c.PasswordHash(), sealed, v.now()); err != nil {
		return fmt.Errorf("write console credential: %w", err)
	}
	return nil
}

// ConsoleReplayStore is the durable implementation of the console TOTP replay guard
// (app.TOTPReplayStore) over the console_totp_replay table (migration 0013). It
// persists the last consumed RFC6238 step per subject so a code cannot be replayed
// across a restart either — a durable credential with an in-memory replay guard would
// re-open the replay window on every restart, so this MUST be durable too. The step
// counter is a monotonic integer, not a secret, so it is stored in the clear.
type ConsoleReplayStore struct {
	db    *sql.DB
	clock ports.Clock
}

// NewConsoleReplayStore wraps a database handle with a clock (for updated_at).
func NewConsoleReplayStore(db *sql.DB, clock ports.Clock) *ConsoleReplayStore {
	return &ConsoleReplayStore{db: db, clock: clock}
}

// LastStep returns the last TOTP step consumed for subject, or 0 when none is
// recorded (the zero step is never a valid counter for a real clock, so a fresh
// subject always passes the step > last check).
func (r *ConsoleReplayStore) LastStep(ctx context.Context, subject string) (int64, error) {
	var step int64
	err := r.db.QueryRowContext(ctx,
		`SELECT last_step FROM console_totp_replay WHERE subject = $1`, subject).Scan(&step)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read console totp replay: %w", err)
	}
	return step, nil
}

// SetLastStep records the TOTP step just consumed for subject so it (and any earlier
// step) cannot be replayed. It upserts on the subject.
func (r *ConsoleReplayStore) SetLastStep(ctx context.Context, subject string, step int64) error {
	if _, err := r.db.ExecContext(ctx,
		`INSERT INTO console_totp_replay (subject, last_step, updated_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (subject) DO UPDATE SET
		     last_step = excluded.last_step,
		     updated_at = excluded.updated_at`,
		subject, step, r.now()); err != nil {
		return fmt.Errorf("write console totp replay: %w", err)
	}
	return nil
}

// now returns the current instant formatted as RFC3339-UTC (the adapter-wide layout).
func (v *ConsoleCredentialVault) now() string {
	return v.clock.Now().UTC().Format(tsLayout)
}

// now returns the current instant formatted as RFC3339-UTC (the adapter-wide layout).
func (r *ConsoleReplayStore) now() string {
	return r.clock.Now().UTC().Format(tsLayout)
}
