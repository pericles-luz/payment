-- GERADO por scripts/gen-pg-migrations.py a partir de ../0017_webhook_ref_revocation.up.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0017_webhook_ref_revocation.up.sql — gives the durable per-tenant webhook-ref
-- store (0016) a lifecycle: soft-delete for revocation and a "supersede on write"
-- invariant so a tenant has AT MOST ONE active callback ref at a time
-- (SIN-69588 / B1, residuals of SIN-69558).
--
-- WHY: 0016's PutWebhookRef was INSERT-OR-IGNORE, pure append. Because the store is
-- hash-only, the in-flow registrar (F2, SIN-69560) cannot recover the plaintext ref
-- minted at POST /v1/clients, so it mints a FRESH one at the cred+key convergence
-- point. Both hashes resolved to the same tenant, so BOTH capability URLs stayed valid
-- forever, and every failed registration attempt left another orphan. There was no way
-- to revoke a ref. This migration adds the missing dimension so PutWebhookRef can
-- supersede (revoke-then-insert in one tx) and a ref can be explicitly revoked.
--
-- revoked_at NULL  = active   (authenticates inbound C6 callbacks)
-- revoked_at set   = revoked  (kept for audit, but LookupWebhookRef ignores it)
--
-- Reversibility: additive (ADD COLUMN only); 0017_*.down.sql drops the column,
-- restoring 0016's exact shape. NULL-safe: every pre-0017 row has revoked_at NULL, so
-- it stays active with identical behaviour to before this migration — no ref that used
-- to authenticate stops doing so on apply. The unique index on ref_sha256 is unchanged
-- (a superseded row keeps its hash; a fresh mint always has a new 256-bit hash).
--
-- Portability (same conventions as 0001..0016): TEXT RFC3339-UTC timestamp, nullable,
-- no SQLite-only types, so it ports to Postgres unchanged.
ALTER TABLE webhook_tenant_refs ADD COLUMN revoked_at TEXT NULL;

-- Hot path is "resolve the ACTIVE ref": lookups filter revoked_at IS NULL and the
-- supersede path revokes a tenant's active rows. A partial index over active rows keyed
-- by tenant keeps both cheap without bloating on revoked history.
CREATE INDEX IF NOT EXISTS ix_webhook_tenant_refs_active
    ON webhook_tenant_refs (tenant_id)
    WHERE revoked_at IS NULL;
