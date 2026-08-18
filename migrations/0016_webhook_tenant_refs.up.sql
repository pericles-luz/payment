-- 0016_webhook_tenant_refs.up.sql — durable store for the opaque per-tenant C6
-- webhook callback reference (tenantRef), phase F1 of SIN-69558 / SIN-69557
-- (umbrella SIN-69486, model (b) ADR-0011).
--
-- WHY: the tenantRef in /webhooks/c6/{tenantRef} IS the per-tenant credential — the
-- C6 webhook is unsigned, so the unguessable URL segment authenticates the channel
-- (ADR-0002 / F4). Until now the ONLY source of refs was the env PAYMENT_WEBHOOK_REFS,
-- read ONCE at boot into an in-memory sha256(ref)->identity map. A client created by
-- POST /v1/clients therefore gained a working callback only if an operator edited the
-- environment AND restarted the process. This table is the durable home of those
-- refs: POST /v1/clients now mints one server-side and persists it here, so a fresh
-- empresa-cliente can receive webhooks WITHOUT an operator and WITHOUT a restart.
--
-- SECURITY (same discipline as the in-memory map and account_keys, 0011): the
-- plaintext ref is a >=256-bit CSPRNG secret and is NEVER stored — only its SHA-256
-- (hex) lands in ref_sha256. Authentication is an indexed lookup by that hash, never
-- a plaintext comparison, so no secret ever appears in a query argument in the clear
-- and there is no per-row timing oracle. No column holds the ref, a URL, or PII.
-- tenant_id references tenants(id) so a ref can only belong to a real tenant; ON
-- DELETE CASCADE removes a tenant's refs with the tenant.
--
-- ENV STAYS AS BOOTSTRAP: PAYMENT_WEBHOOK_REFS keeps working — it seeds the in-memory
-- map at boot, and the authenticator falls back to THIS table on a map miss. Same
-- env-as-bootstrap / DB-as-durable pattern as the bank/console credential vaults.
--
-- Reversibility: purely additive (CREATE TABLE + CREATE INDEX); 0016_*.down.sql drops
-- them in index-before-table order. Touches no existing table, so rollback is a clean
-- drop — the env bootstrap alone then serves refs exactly as before this migration.
--
-- Portability (same conventions as 0001..0015): TEXT opaque id / hash, TEXT
-- RFC3339-UTC timestamp, no SQLite-only types, so it ports to Postgres unchanged.
CREATE TABLE IF NOT EXISTS webhook_tenant_refs (
    ref_sha256 TEXT NOT NULL, -- hex SHA-256 of the plaintext ref; NEVER the ref itself
    tenant_id  TEXT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    created_at TEXT NOT NULL  -- RFC3339-UTC mint instant
);

-- Authentication is a lookup by hash (WHERE ref_sha256 = ?); UNIQUE both indexes the
-- hot path AND guarantees one identity per ref (two distinct 256-bit secrets colliding
-- on SHA-256 is infeasible, and re-minting the same ref is not a real path).
CREATE UNIQUE INDEX IF NOT EXISTS ux_webhook_tenant_refs_hash
    ON webhook_tenant_refs (ref_sha256);
