-- GERADO por scripts/gen-pg-migrations.py a partir de ../0012_bank_secret_vault.down.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0012_bank_secret_vault.down.sql — backward-compatible rollback of 0012.
--
-- Drops the two durable bank secret vaults. Reversible by re-applying 0012.up (which
-- recreates the empty tables). No other table referenced them, so nothing else
-- changes. Rolling back discards any runtime-configured credential/certificate that
-- was persisted here — acceptable because with PAYMENT_BANK_VAULT_KEY unset the
-- in-memory vaults are used and this schema is inert; a deployment relying on the
-- durable vault must re-provision from env/console after a rollback (same posture as
-- the pre-0012 in-memory behaviour).
--
-- No indexes beyond the implicit PRIMARY KEY, so drop the tables directly.
DROP TABLE IF EXISTS bank_certificates;
DROP TABLE IF EXISTS bank_credentials;
