-- 0001_init.down.sql — backward-compatible rollback of 0001_init.up.sql.
-- Drops in reverse dependency order.
DROP TABLE IF EXISTS processed_events;
DROP TABLE IF EXISTS billing_ledger;
DROP TABLE IF EXISTS endpoint_pricing;
DROP INDEX IF EXISTS ix_payments_tenant_tx;
DROP INDEX IF EXISTS ux_payments_tenant_idempotency;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS tenants;
