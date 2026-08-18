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

// PutWebhookRef binds a minted ref (by its SHA-256) to tenantID. The hash is stored
// hex-encoded (TEXT, portable to Postgres); the plaintext ref never reaches here. A
// duplicate hash (idempotent re-mint of the same ref — not a real path) is a no-op via
// INSERT OR IGNORE, so a retry never errors on the unique index. tenant_id is FK-checked
// against tenants(id), so a ref for a non-existent tenant fails closed rather than
// dangling.
func (s *WebhookRefStore) PutWebhookRef(ctx context.Context, refSHA []byte, tenantID string) error {
	if len(refSHA) == 0 {
		return shared.NewValidationError("ref_sha256", "ref hash is required")
	}
	if tenantID == "" {
		return shared.NewValidationError("tenant_id", "tenant id is required")
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO webhook_tenant_refs (ref_sha256, tenant_id, created_at)
		 VALUES (?, ?, ?)`,
		hex.EncodeToString(refSHA), tenantID, s.clock.Now().UTC().Format(tsLayout)); err != nil {
		return fmt.Errorf("insert webhook ref: %w", err)
	}
	return nil
}

// LookupWebhookRef resolves a ref's SHA-256 to its owning tenant id via an indexed
// lookup of its hex hash. An unknown ref returns ("", false, nil) — the same non-oracle
// miss as the in-memory map. Any OTHER read error is surfaced (non-nil error) so the
// authenticator fails CLOSED on an infrastructure fault rather than silently treating a
// transient error as "no such ref". The ref itself is never sent to the database; only
// its hash is.
func (s *WebhookRefStore) LookupWebhookRef(ctx context.Context, refSHA []byte) (string, bool, error) {
	if len(refSHA) == 0 {
		return "", false, nil
	}
	var tenantID string
	err := s.db.QueryRowContext(ctx,
		`SELECT tenant_id FROM webhook_tenant_refs WHERE ref_sha256 = ?`,
		hex.EncodeToString(refSHA)).Scan(&tenantID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil // unregistered ref — non-oracle miss
	case err != nil:
		return "", false, fmt.Errorf("lookup webhook ref: %w", err)
	default:
		return tenantID, true, nil
	}
}
