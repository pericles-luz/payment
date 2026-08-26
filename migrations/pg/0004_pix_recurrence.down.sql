-- GERADO por scripts/gen-pg-migrations.py a partir de ../0004_pix_recurrence.down.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0004_pix_recurrence.down.sql — backward-compatible rollback of 0004.
-- Drops the PIX Automático recurrence tables. The audit_log trail of past
-- transitions is unaffected (it lives in its own table); only the current-state
-- mandate and charge records are removed. Reversible by re-applying 0004.up.
DROP TABLE IF EXISTS pix_cobr;
DROP TABLE IF EXISTS pix_rec;
