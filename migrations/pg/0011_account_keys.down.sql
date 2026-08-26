-- GERADO por scripts/gen-pg-migrations.py a partir de ../0011_account_keys.down.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0011_account_keys.down.sql — backward-compatible rollback of 0011.
--
-- Drops the account-key credential store. Reversible by re-applying 0011.up (which
-- recreates the empty table + indexes). No other table carried an account_keys
-- reference, so nothing else changes. Any keys emitted are discarded on rollback —
-- acceptable because the whole model (b) path is flag-gated and, per ADR-0011
-- Reversibility, turning the flag off already makes emitted keys inert.
--
-- Order: drop the indexes that reference the table before the table itself.
DROP INDEX IF EXISTS ix_account_keys_account;
DROP INDEX IF EXISTS ix_account_keys_hash;
DROP TABLE IF EXISTS account_keys;
