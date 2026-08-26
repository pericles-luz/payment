-- GERADO por scripts/gen-pg-migrations.py a partir de ../0001_init.up.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0001_init.up.sql — foundation schema.
-- Portable SQL targeting SQLite now and Postgres later. Notes on portability:
--   * TEXT primary keys (opaque random ids) — portable.
--   * INTEGER for cents — maps to BIGINT in Postgres; values fit in int64.
--   * Timestamps stored as TEXT (RFC3339 UTC) for cross-engine portability;
--     in Postgres these can become TIMESTAMPTZ in a follow-up migration.
--   * No SQLite-specific types (no AUTOINCREMENT, no ROWID reliance).
-- Multi-tenancy: every business table carries tenant_id and is queried scoped.

CREATE TABLE IF NOT EXISTS tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1, -- 0/1 boolean; Postgres: BOOLEAN
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    endpoint        TEXT NOT NULL,
    amount_cents    BIGINT NOT NULL,
    currency        TEXT NOT NULL,
    status          TEXT NOT NULL,
    tx_id           TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    CONSTRAINT fk_payments_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id)
);

-- Idempotency is scoped per tenant: the same key may exist for different tenants.
CREATE UNIQUE INDEX IF NOT EXISTS ux_payments_tenant_idempotency
    ON payments (tenant_id, idempotency_key);

-- Tenant-scoped lookups by tx id (reconciliation).
CREATE INDEX IF NOT EXISTS ix_payments_tenant_tx
    ON payments (tenant_id, tx_id);

-- Per-tenant per-endpoint pricing.
CREATE TABLE IF NOT EXISTS endpoint_pricing (
    tenant_id   TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    price_cents BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, endpoint),
    CONSTRAINT fk_pricing_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id)
);

-- Append-only billing ledger (authoritative for what a tenant was charged).
CREATE TABLE IF NOT EXISTS billing_ledger (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    price_cents BIGINT NOT NULL,
    reference   TEXT NOT NULL DEFAULT '',
    at          TEXT NOT NULL,
    CONSTRAINT fk_ledger_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id)
);

CREATE INDEX IF NOT EXISTS ix_ledger_tenant ON billing_ledger (tenant_id);

-- Processed external events for webhook idempotency / anti-replay.
CREATE TABLE IF NOT EXISTS processed_events (
    tenant_id    TEXT NOT NULL,
    event_key    TEXT NOT NULL,
    processed_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, event_key)
);
