-- GERADO por scripts/gen-pg-migrations.py a partir de ../0002_audit_log.up.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0002_audit_log.up.sql — durable, append-only audit trail (SIN-66025 / SIN-66016).
--
-- Persists the privileged admin-plane and money-movement audit entries the
-- application already emits (audit.Entry), so the forensic/compliance trail
-- survives a process restart (OWASP A09). Append-only by contract: the adapter
-- only ever INSERTs — there is NO UPDATE/DELETE path in application code.
--
-- SECURITY: this table carries only who/what/tenant/when (+ the txid and the
-- expected/received cents for a settlement-mismatch event). It NEVER stores a
-- secret, a credential, a client id or any PII — mirroring audit.Entry, which has
-- no secret field by construction (threat C1/C4).
--
-- Portability (same conventions as 0001_init): TEXT opaque ids, TEXT RFC3339-UTC
-- timestamps, INTEGER cents (BIGINT in Postgres). No SQLite-only types/pragmas in
-- the logical schema, so the table ports to Postgres unchanged.
CREATE TABLE IF NOT EXISTS audit_log (
    id             TEXT PRIMARY KEY,
    -- operator_id is the server-derived pseudonymous actor. Empty for a
    -- non-attributed internal caller; a reserved synthetic id (e.g.
    -- 'system:c6-webhook') for a system actor. Never a real name/credential.
    operator_id    TEXT NOT NULL DEFAULT '',
    action         TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    at             TEXT NOT NULL,
    -- tx_id / expected_cents / received_cents are populated only for money-movement
    -- events (settlement.amount_mismatch); zero/empty for admin-plane actions.
    tx_id          TEXT NOT NULL DEFAULT '',
    expected_cents BIGINT NOT NULL DEFAULT 0,
    received_cents BIGINT NOT NULL DEFAULT 0
);

-- Forensic queries: "what happened to this tenant, in time order" and
-- "every occurrence of this action, in time order".
CREATE INDEX IF NOT EXISTS ix_audit_tenant_at ON audit_log (tenant_id, at);
CREATE INDEX IF NOT EXISTS ix_audit_action_at ON audit_log (action, at);
