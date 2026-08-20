-- GERADO por scripts/gen-pg-migrations.py a partir de ../0005_terms_consent.down.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0005_terms_consent.down.sql — backward-compatible rollback of
-- 0005_terms_consent.up.sql. Drops the index then the table (reverse dependency
-- order). terms_consent is append-only compliance evidence; a real production
-- rollback should archive it first (LGPD retention obligation).
DROP INDEX IF EXISTS ix_terms_consent_lookup;
DROP TABLE IF EXISTS terms_consent;
