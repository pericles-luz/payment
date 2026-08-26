-- GERADO por scripts/gen-pg-migrations.py a partir de ../0007_two_level_tenancy.up.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0007_two_level_tenancy.up.sql — foundation of the two-level tenancy model
-- (SIN-69124 / trilha A F0 of the C6 go-live SIN-69118; design SIN-69119; ADR-0009).
--
-- Adds an Account level ABOVE the tenant. An account is the API user / reseller
-- (e.g. Verz); a tenant is the empresa-cliente that owns its own C6 credential and
-- receives its own money (model (a), PSP-Indireto pass-through). The account is
-- attribution-only: it identifies who a token belongs to and is the billing rollup
-- target, but it NEVER holds a bank credential and NEVER touches money.
--
-- SHIPS DARK: no /v1 route, no auth path, no metering row and no (tenant,bank)
-- credential changes shape here. This migration only widens the schema and backfills
-- a self-account per existing tenant, so the flat legacy model becomes "an account of
-- one tenant, 1:1" with identical behaviour (ADR-0009 §4).
--
-- SCOPE: adds accounts + tenants.account_id + billing_ledger.account_id (design §6 F0
-- row). audit_log.account_id (design §4) is deferred — see the note near the end.
--
-- Reversibility: every step is additive (CREATE TABLE / ADD COLUMN / backfill /
-- CREATE INDEX); 0007_*.down.sql drops them in FK-safe order. NULL-safe semantics:
-- an account_id left NULL means "the tenant's self-account" during any window where a
-- row has not been backfilled or reprovisioned.
--
-- Portability (same conventions as 0001/0002/0006): TEXT opaque ids, TEXT RFC3339-UTC
-- timestamps, INTEGER 0/1 booleans (BOOLEAN in Postgres). No SQLite-only types, so the
-- schema ports to Postgres unchanged.

-- The API user / reseller aggregate. Mirrors tenants deliberately (same columns) so
-- the admin plane and persistence reuse the tenant shape. No credential column.
CREATE TABLE IF NOT EXISTS accounts (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1, -- 0/1 boolean; Postgres: BOOLEAN
    created_at TEXT NOT NULL
);

-- The owning account of each tenant. NULL = self-account (NULL-safe legacy semantics).
-- FK enforces that a non-NULL owner references a real account. Default NULL keeps the
-- ADD COLUMN legal under enabled foreign_keys and requires no data for pre-existing rows.
ALTER TABLE tenants ADD COLUMN account_id TEXT NULL REFERENCES accounts (id);

-- Backfill: mint a self-account 1:1 for every existing tenant. The account id is
-- DERIVED deterministically ('acct-' || tenant.id) so the mapping is reproducible and
-- the down migration needs no bookkeeping; name/active/created_at mirror the tenant.
INSERT INTO accounts (id, name, active, created_at)
    SELECT 'acct-' || id, name, active, created_at FROM tenants;

-- Point every legacy tenant at its freshly-minted self-account (only where still NULL,
-- so re-running after a partial apply is safe).
UPDATE tenants SET account_id = 'acct-' || id WHERE account_id IS NULL;

-- Metering rollup: the billing ledger gains the account dimension so a future invoice
-- can group account -> tenant(empresa-cliente) -> endpoint. Backfilled from the tenant's
-- self-account; the (account_id, at) index supports the time-ordered rollup scan.
ALTER TABLE billing_ledger ADD COLUMN account_id TEXT NULL;
UPDATE billing_ledger SET account_id = 'acct-' || tenant_id WHERE account_id IS NULL;
CREATE INDEX IF NOT EXISTS ix_ledger_account_at ON billing_ledger (account_id, at);

-- NOTE: audit_log.account_id (design §4, "completude forense do rollup por usuário-API")
-- is intentionally NOT added here. A schema-whitelist security test
-- (TestAuditSchemaCarriesNoSecretColumn) pins the exact audit_log column set to bar an
-- accidental secret-bearing column (threat C1/C4); adding account_id requires a one-line
-- update to that test's allow-list (the same maintenance bank_id needed in 0003/SIN-66044),
-- which needs CTO authorization per the test-immutability rule. It is deferred to F2 (where
-- account is stamped on new writes) — the backfill `SET account_id = 'acct-' || tenant_id`
-- is equally correct whenever the column is added, so no forensic data is lost by waiting.

-- endpoint_pricing stays keyed by tenant (price per empresa-cliente already comes for
-- free) — intentionally NOT touched.
