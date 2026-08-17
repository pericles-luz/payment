package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/secret"
	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundwebhook"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// OutboundWebhookVault is the durable, ENCRYPTED-AT-REST implementation of the
// per-Conta outbound webhook config store (SIN-69490, F0 of SIN-69486). It backs the
// account_outbound_webhook table (migration 0014) and satisfies the app-layer
// app.OutboundWebhookStore port — Get/Upsert/Delete keyed by accountID — so cmd wiring
// swaps it into ConsoleService and the console CRUD persists durably.
//
// SECURITY (mirrors the bank secret vault, SIN-69366, and the console credential
// vault, SIN-69432): the HMAC signing secret is the only true secret at rest and is
// sealed with secret.SealWithAAD (AES-256-GCM) BEFORE it touches a column, so the
// durable bytes are ciphertext, never plaintext. The seal is bound to the row's
// account_id via secret.OutboundWebhookAAD (a sealed secret copied to another Conta's
// row then fails to open). The URL is NOT a secret (the operator sees it on the card)
// and is stored in the clear; the enabled toggle is a boolean. The AES key is the SAME
// KEK as the bank vault (PAYMENT_BANK_VAULT_KEY), held only in the injected
// *secret.Cipher. Nothing here is ever logged.
type OutboundWebhookVault struct {
	db     *sql.DB
	cipher *secret.Cipher
	clock  ports.Clock
}

// NewOutboundWebhookVault wraps a database handle with the sealing cipher and a clock
// (injected so created_at/updated_at stay deterministic in tests). The cipher MUST be
// non-nil: a store that cannot encrypt the signing secret must not exist (fail-closed
// at wiring — the caller only builds this when PAYMENT_BANK_VAULT_KEY is set).
func NewOutboundWebhookVault(db *sql.DB, cipher *secret.Cipher, clock ports.Clock) *OutboundWebhookVault {
	return &OutboundWebhookVault{db: db, cipher: cipher, clock: clock}
}

// GetOutboundWebhook returns the Conta's outbound webhook config, or
// shared.ErrNotFound when none is configured. The sealed signing secret is opened
// (decrypted) transiently for the rehydrated aggregate and never logged. A decrypt
// failure (tamper / wrong key / row relocation) surfaces as an error so a corrupted
// config is never silently accepted (fail-closed).
func (v *OutboundWebhookVault) GetOutboundWebhook(ctx context.Context, accountID string) (*outboundwebhook.Config, error) {
	var (
		url          string
		sealedSecret []byte
		enabled      int
		createdAt    string
		updatedAt    string
	)
	err := v.db.QueryRowContext(ctx,
		`SELECT url, signing_secret_sealed, enabled, created_at, updated_at
		   FROM account_outbound_webhook WHERE account_id = ?`, accountID).
		Scan(&url, &sealedSecret, &enabled, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read outbound webhook: %w", err)
	}
	signingSecret, err := v.cipher.OpenWithAAD(sealedSecret, secret.OutboundWebhookAAD(accountID))
	if err != nil {
		return nil, fmt.Errorf("open outbound webhook signing secret: %w", err)
	}
	return outboundwebhook.Rehydrate(accountID, url, string(signingSecret), enabled != 0,
		parseTime(createdAt), parseTime(updatedAt)), nil
}

// UpsertOutboundWebhook persists (create or update) a Conta's outbound webhook config,
// keyed by account_id. The signing secret is sealed (bound to the account id) before
// it reaches the column — never plaintext at rest. created_at is preserved on update
// (the INSERT value is only used on first insert); updated_at is taken from the
// aggregate so it tracks the domain mutation instant.
func (v *OutboundWebhookVault) UpsertOutboundWebhook(ctx context.Context, cfg *outboundwebhook.Config) error {
	sealed, err := v.cipher.SealWithAAD([]byte(cfg.SigningSecret()), secret.OutboundWebhookAAD(cfg.AccountID()))
	if err != nil {
		return fmt.Errorf("seal outbound webhook signing secret: %w", err)
	}
	enabled := 0
	if cfg.Enabled() {
		enabled = 1
	}
	if _, err := v.db.ExecContext(ctx,
		`INSERT INTO account_outbound_webhook (account_id, url, signing_secret_sealed, enabled, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (account_id) DO UPDATE SET
		     url = excluded.url,
		     signing_secret_sealed = excluded.signing_secret_sealed,
		     enabled = excluded.enabled,
		     updated_at = excluded.updated_at`,
		cfg.AccountID(), cfg.URL(), sealed, enabled,
		cfg.CreatedAt().UTC().Format(tsLayout), cfg.UpdatedAt().UTC().Format(tsLayout)); err != nil {
		return fmt.Errorf("write outbound webhook: %w", err)
	}
	return nil
}

// DeleteOutboundWebhook hard-deletes a Conta's outbound webhook config. It is
// IDEMPOTENT — deleting an absent config is a no-op that still returns nil — so a
// repeated "remover" click is harmless. The whole row (including the sealed secret) is
// dropped, so no secret material lingers.
func (v *OutboundWebhookVault) DeleteOutboundWebhook(ctx context.Context, accountID string) error {
	if _, err := v.db.ExecContext(ctx,
		`DELETE FROM account_outbound_webhook WHERE account_id = ?`, accountID); err != nil {
		return fmt.Errorf("delete outbound webhook: %w", err)
	}
	return nil
}
