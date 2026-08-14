-- 0010_audit_origin.down.sql — backward-compatible rollback of 0010.
--
-- Drops the origin dimension, restoring the exact column set 0009 left in place
-- (which the schema-whitelist test pins). audit_log rows keep who/what/tenant/when
-- (+ txid, cents, bank_id, account_id); only the surface-attribution label is
-- removed. Reversible by re-applying 0010.up (whose DEFAULT 'admin' re-establishes
-- the admin-only baseline, so no forensic data is lost across a down/up cycle).
ALTER TABLE audit_log DROP COLUMN origin;
