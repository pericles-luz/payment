-- 0009_audit_account_id.up.sql — completes the two-level tenancy rollup on the
-- audit trail (SIN-69127 / trilha A F2 of the C6 go-live SIN-69118; design SIN-69119 §4;
-- ADR-0009). This is the deferred half of 0007: that migration added the account
-- dimension to tenants and billing_ledger but intentionally left audit_log alone (a
-- schema-whitelist security test pins its exact column set — see the note at the end
-- of 0007_two_level_tenancy.up.sql). With CTO authorization to update that test's
-- allow-list by one line, the audit trail now gains the same attribution column so the
-- forensic record of privileged/system actions is complete per account→tenant rollup.
--
-- SHIPS DARK: account_id is attribution-only. It NEVER holds a bank credential and
-- NEVER touches money (model (a), PSP-Indireto). No route, auth path or (tenant,bank)
-- credential shape changes here — this migration only widens audit_log and backfills a
-- self-account per existing row.
--
-- Reversibility: additive (ADD COLUMN + backfill); 0009_*.down.sql drops the column.
-- NULL-safe: a NULL account_id means "the audited tenant's self-account" during any
-- window where a row was written before this migration and not yet backfilled.
--
-- Portability (same conventions as 0001..0007): TEXT opaque id, no SQLite-only types,
-- so it ports to Postgres unchanged.

-- The owning account of the audited tenant. NULL = self-account (NULL-safe legacy
-- semantics). It carries NO secret (threat C1/C4): 'acct-<tenant_id>' is a public,
-- deterministic attribution id, exactly like the tenant id already stored here.
ALTER TABLE audit_log ADD COLUMN account_id TEXT NULL;

-- Backfill: attribute every existing audit row to its tenant's self-account, DERIVED
-- deterministically ('acct-' || tenant_id) — identical to 0007's ledger/tenant backfill
-- and to account.SelfAccountID in code, so the trail cannot diverge from the real owner.
UPDATE audit_log SET account_id = 'acct-' || tenant_id WHERE account_id IS NULL;
