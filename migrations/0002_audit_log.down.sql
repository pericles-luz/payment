-- 0002_audit_log.down.sql — backward-compatible rollback of 0002_audit_log.up.sql.
-- Drops the indexes then the table (reverse dependency order). The audit trail is
-- append-only forensic data; a real production rollback should archive it first.
DROP INDEX IF EXISTS ix_audit_action_at;
DROP INDEX IF EXISTS ix_audit_tenant_at;
DROP TABLE IF EXISTS audit_log;
