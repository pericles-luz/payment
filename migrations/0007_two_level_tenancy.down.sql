-- 0007_two_level_tenancy.down.sql — backward-compatible rollback of 0007.
--
-- Restores the flat one-level model: drops the account dimension from the ledger,
-- the audit trail and the tenants table, then drops the accounts table. The money
-- records (payments), pricing (endpoint_pricing) and the (tenant,bank) credential
-- store are untouched — they never carried an account column. Reversible by
-- re-applying 0007.up (which re-backfills the self-accounts deterministically).
--
-- Order matters (SQLite DROP COLUMN restrictions): drop the index that references
-- billing_ledger.account_id BEFORE dropping the column; drop the tenants.account_id
-- FK column BEFORE dropping the accounts table it references. (audit_log.account_id is
-- not added by 0007.up — deferred to F2 — so there is nothing to drop here for it.)
DROP INDEX IF EXISTS ix_ledger_account_at;
ALTER TABLE billing_ledger DROP COLUMN account_id;
ALTER TABLE tenants DROP COLUMN account_id;
DROP TABLE IF EXISTS accounts;
