-- 0008_invoices.down.sql — backward-compatible rollback of 0008_invoices.up.sql.
-- Drops the tenant listing index, then the line-item table (child), then the
-- invoice header table (parent) — reverse dependency order so the FK from
-- invoice_items -> invoices is never left dangling. Invoices are append-only
-- billing evidence; a real production rollback should archive them first.
DROP INDEX IF EXISTS ix_invoices_tenant;
DROP TABLE IF EXISTS invoice_items;
DROP TABLE IF EXISTS invoices;
