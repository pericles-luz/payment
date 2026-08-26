-- GERADO por scripts/gen-pg-migrations.py a partir de ../0015_account_outbound_delivery.down.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0015_account_outbound_delivery.down.sql — backward-compatible rollback of 0015.
--
-- Drops the per-Conta outbound-delivery outbox and the dead-letter park. Reversible by
-- re-applying 0015.up (which recreates both empty tables and their indexes). No other
-- table referenced them, so nothing else changes. Rolling back discards any queued/
-- parked events — acceptable because the feature is DARK behind
-- PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK (default-off) and performs no forwarding in F1, so
-- no live delivery depends on it.
--
-- Dropping a table drops its indexes implicitly; drop the tables directly.
DROP TABLE IF EXISTS account_outbound_dead_letter;
DROP TABLE IF EXISTS account_outbound_delivery;
