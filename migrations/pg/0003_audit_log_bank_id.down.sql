-- GERADO por scripts/gen-pg-migrations.py a partir de ../0003_audit_log_bank_id.down.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0003_audit_log_bank_id.down.sql — backward-compatible rollback of 0003.
-- Drops the additive bank_id column. The remaining who/what/tenant/when trail is
-- unaffected; only the per-bank attribution on credential.set events is lost.
-- (SQLite 3.35+ and Postgres both support DROP COLUMN.)
ALTER TABLE audit_log DROP COLUMN bank_id;
