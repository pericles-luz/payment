package sqlite

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// WebhookRefStore is the durable, hash-at-rest implementation of
// ports.WebhookRefStore over the webhook_tenant_refs table (migration 0016). It
// satisfies the SAME port as the in-memory adapter, so wiring swaps one for the other
// without the use-cases knowing (SIN-69559 / F1).
//
// It is intentionally its own struct with its own *sql.DB rather than a method set on
// Store: a webhook ref is a capability credential, not a financial aggregate, so it
// stays out of the payment Repository / unit-of-work bundle (same rationale as
// AccountKeyStore).
//
// SECURITY (ADR-0002 / F4, same discipline as account_keys): the plaintext ref is
// never persisted — the caller hashes it (webhookref.Sum) before it reaches this
// adapter, and only the hex SHA-256 is written to ref_sha256. Resolution is an indexed
// lookup by that hash, never a plaintext comparison, so no secret appears in a query
// argument in the clear and there is no per-row timing oracle.
type WebhookRefStore struct {
	db    *sql.DB
	clock ports.Clock
}

// NewWebhookRefStore wraps a database handle. The clock is injected so the mint
// timestamp stays deterministic in tests (same convention as the other adapters).
func NewWebhookRefStore(db *sql.DB, clock ports.Clock) *WebhookRefStore {
	return &WebhookRefStore{db: db, clock: clock}
}

// Compile-time check that the adapter satisfies the port.
var _ ports.WebhookRefStore = (*WebhookRefStore)(nil)

// PutWebhookRef binds a minted ref (by its SHA-256) to tenantID with SUPERSEDE
// semantics (SIN-69588 / B1): in ONE transaction it revokes every OTHER ref currently
// active for the tenant, then upserts this one as the single active ref. So a tenant
// converges on AT MOST ONE active callback ref — the F1 store was pure-append before,
// which left every minted ref valid forever and accumulated an orphan on each failed
// registration attempt. The hash is stored hex-encoded (TEXT, portable to Postgres);
// the plaintext ref never reaches here. Re-putting the SAME hash is idempotent and
// re-activates it (revoked_at cleared) without revoking itself. tenant_id is FK-checked
// against tenants(id), so a ref for a non-existent tenant fails closed rather than
// dangling.
func (s *WebhookRefStore) PutWebhookRef(ctx context.Context, refSHA []byte, tenantID string) error {
	if len(refSHA) == 0 {
		return shared.NewValidationError("ref_sha256", "ref hash is required")
	}
	if tenantID == "" {
		return shared.NewValidationError("tenant_id", "tenant id is required")
	}
	hexSHA := hex.EncodeToString(refSHA)
	now := s.clock.Now().UTC().Format(tsLayout)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin webhook ref tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after a successful Commit

	// Supersede: revoke the tenant's OTHER active refs. Excluding this exact hash keeps a
	// re-put idempotent — it must never revoke the very ref it is about to (re)activate.
	if _, err := tx.ExecContext(ctx,
		`UPDATE webhook_tenant_refs SET revoked_at = ?
		 WHERE tenant_id = ? AND revoked_at IS NULL AND ref_sha256 <> ?`,
		now, tenantID, hexSHA); err != nil {
		return fmt.Errorf("supersede active webhook refs: %w", err)
	}
	// Insert the new active ref. On a hash re-put (not a real path — a fresh 256-bit ref
	// never collides) clear any prior revoked_at so the ref is active again, and never
	// error on the unique index, so a retry is safe.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO webhook_tenant_refs (ref_sha256, tenant_id, created_at, revoked_at)
		 VALUES (?, ?, ?, NULL)
		 ON CONFLICT(ref_sha256) DO UPDATE SET revoked_at = NULL, tenant_id = excluded.tenant_id`,
		hexSHA, tenantID, now); err != nil {
		return fmt.Errorf("insert webhook ref: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit webhook ref tx: %w", err)
	}
	return nil
}

// RevokeWebhookRefs soft-deletes every ref currently active for tenantID by stamping
// revoked_at, so none of them authenticate an inbound callback afterwards (SIN-69588 /
// B1 — the revocation path). Rows are kept for audit, not deleted. Idempotent: a tenant
// with no active ref revokes zero rows and returns (0, nil).
func (s *WebhookRefStore) RevokeWebhookRefs(ctx context.Context, tenantID string) (int, error) {
	if tenantID == "" {
		return 0, shared.NewValidationError("tenant_id", "tenant id is required")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE webhook_tenant_refs SET revoked_at = ?
		 WHERE tenant_id = ? AND revoked_at IS NULL`,
		s.clock.Now().UTC().Format(tsLayout), tenantID)
	if err != nil {
		return 0, fmt.Errorf("revoke webhook refs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("revoke webhook refs rows affected: %w", err)
	}
	return int(n), nil
}

// LookupWebhookRef resolves an ACTIVE ref's SHA-256 to its owning tenant id via an
// indexed lookup of its hex hash. A revoked ref (revoked_at IS NOT NULL) or an unknown
// ref both return ("", false, nil) — the same non-oracle miss as the in-memory map, so
// a revoked ref stops authenticating exactly like an unregistered one. Any OTHER read
// error is surfaced (non-nil error) so the authenticator fails CLOSED on an
// infrastructure fault rather than silently treating a transient error as "no such ref".
// The ref itself is never sent to the database; only its hash is.
func (s *WebhookRefStore) LookupWebhookRef(ctx context.Context, refSHA []byte) (string, bool, error) {
	if len(refSHA) == 0 {
		return "", false, nil
	}
	var tenantID string
	err := s.db.QueryRowContext(ctx,
		`SELECT tenant_id FROM webhook_tenant_refs WHERE ref_sha256 = ? AND revoked_at IS NULL`,
		hex.EncodeToString(refSHA)).Scan(&tenantID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil // unregistered OR revoked ref — non-oracle miss
	case err != nil:
		return "", false, fmt.Errorf("lookup webhook ref: %w", err)
	default:
		return tenantID, true, nil
	}
}
