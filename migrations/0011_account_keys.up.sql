-- 0011_account_keys.up.sql — durable store for the rotatable account-key bearer
-- credential (SIN-69278 / phase B1 of ADR-0011 model (b), umbrella SIN-69118).
--
-- WHY: model (b) gives each Account (the API user / reseller, e.g. Verz — accounts
-- table from 0007) ONE rotatable bearer key it presents to access the API, paired
-- with a per-request client selector (ADR-0011 §3). This table is the hash-at-rest
-- home of that key. The plaintext secret is >=256-bit CSPRNG entropy and is NEVER
-- stored: only its SHA-256 hash lands here (threat T5; ADR-0011 §3). Key rotation is
-- create==rotate (SIN-69196): a new active row supersedes the previous (active=0,
-- rotated_at set), so history is retained but only one row per account is active.
--
-- SHIPS DARK: no /v1 route, no auth path and no flag reads this table yet (that is
-- phase B2/B3). This migration only widens the schema; production behaviour is
-- unchanged until PAYMENT_ACCOUNT_KEY_SELECTOR is turned on for a specific account.
--
-- SECURITY: key_hash is a one-way SHA-256 of a high-entropy secret — not reversible
-- and not brute-forceable — but it is still credential-derived material, so it is
-- never logged (domain LogValue redacts it). No column holds the plaintext, a client
-- id, or PII. account_id references accounts(id) so a key can only belong to a real
-- account; ON DELETE CASCADE removes an account's keys with the account.
--
-- Reversibility: additive (CREATE TABLE + CREATE INDEX); 0011_*.down.sql drops them
-- in index-before-table order. Does NOT touch tenants, billing_ledger or audit_log.
--
-- Portability (same conventions as 0001..0010): TEXT opaque ids/hash, TEXT
-- RFC3339-UTC timestamps, INTEGER 0/1 boolean (BOOLEAN in Postgres), no SQLite-only
-- types, so it ports to Postgres unchanged.
CREATE TABLE IF NOT EXISTS account_keys (
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    key_hash   TEXT NOT NULL, -- hex SHA-256 of the plaintext secret; never the secret itself
    active     INTEGER NOT NULL DEFAULT 1, -- 0/1 boolean; Postgres: BOOLEAN
    created_at TEXT NOT NULL, -- RFC3339-UTC mint instant
    rotated_at TEXT NULL      -- RFC3339-UTC supersede instant; NULL while active
);

-- Authenticate is a lookup by hash over active keys (WHERE key_hash = ? AND active = 1),
-- so index by hash. NOT unique: a rotated (inactive) key keeps its historical hash row,
-- and two distinct 256-bit secrets colliding on SHA-256 is infeasible; uniqueness of the
-- ACTIVE key per account is enforced by the write path (supersede-then-insert), not here.
CREATE INDEX IF NOT EXISTS ix_account_keys_hash ON account_keys (key_hash);

-- Rotation and per-account reads scan by account; index the active-key lookup.
CREATE INDEX IF NOT EXISTS ix_account_keys_account ON account_keys (account_id, active);
