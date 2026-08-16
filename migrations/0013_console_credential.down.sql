-- 0013_console_credential.down.sql — backward-compatible rollback of 0013.
--
-- Drops the durable console credential store and its TOTP replay guard. Reversible by
-- re-applying 0013.up (which recreates the empty tables). No other table referenced
-- them, so nothing else changes. Rolling back discards the persisted console
-- credential — acceptable because with PAYMENT_BANK_VAULT_KEY unset the in-memory
-- console store is used and this schema is inert; a deployment relying on the durable
-- store must re-run /console/bootstrap after a rollback (same posture as the pre-0013
-- in-memory behaviour).
--
-- No indexes beyond the implicit PRIMARY KEY, so drop the tables directly.
DROP TABLE IF EXISTS console_totp_replay;
DROP TABLE IF EXISTS console_credential;
