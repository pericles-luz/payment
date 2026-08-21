-- GERADO por scripts/gen-pg-migrations.py a partir de ../0016_webhook_tenant_refs.down.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0016_webhook_tenant_refs.down.sql — backward-compatible rollback of 0016.
--
-- Drops the durable per-tenant webhook-ref store. Reversible by re-applying 0016.up
-- (which recreates the empty table + index). No other table carried a
-- webhook_tenant_refs reference, so nothing else changes. Any refs minted since 0016
-- are discarded on rollback — acceptable because PAYMENT_WEBHOOK_REFS (the env
-- bootstrap) keeps serving refs exactly as it did before this migration, so the
-- webhook channel does not break; only the no-restart durability is rolled back.
--
-- Order: drop the index that references the table before the table itself.
DROP INDEX IF EXISTS ux_webhook_tenant_refs_hash;
DROP TABLE IF EXISTS webhook_tenant_refs;
