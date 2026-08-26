-- GERADO por scripts/gen-pg-migrations.py a partir de ../0009_audit_account_id.down.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0009_audit_account_id.down.sql — backward-compatible rollback of 0009.
--
-- Drops the account dimension from the audit trail, restoring the exact column set
-- 0007 left in place (which the schema-whitelist test pins). audit_log rows keep
-- who/what/tenant/when (+ txid, cents, bank_id); only the derived attribution column
-- is removed. Reversible by re-applying 0009.up (which re-backfills self-accounts
-- deterministically, so no forensic data is lost across a down/up cycle).
ALTER TABLE audit_log DROP COLUMN account_id;
