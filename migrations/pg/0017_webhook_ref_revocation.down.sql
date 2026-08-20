-- GERADO por scripts/gen-pg-migrations.py a partir de ../0017_webhook_ref_revocation.down.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0017_webhook_ref_revocation.down.sql — backward-compatible rollback of 0017.
--
-- Drops the active-ref partial index and the revoked_at column, restoring the exact
-- webhook_tenant_refs shape 0016 created. Rows keep ref_sha256 / tenant_id / created_at.
-- Any refs revoked since 0017 become active again on rollback — acceptable because the
-- inbound callback channel still authenticates by hash exactly as it did before this
-- migration; only the revoke/supersede lifecycle is rolled back. Reversible by
-- re-applying 0017.up (which re-adds the nullable column, all rows active again).
--
-- Order: drop the index that references the column before dropping the column.
DROP INDEX IF EXISTS ix_webhook_tenant_refs_active;
ALTER TABLE webhook_tenant_refs DROP COLUMN revoked_at;
