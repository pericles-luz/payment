-- GERADO por scripts/gen-pg-migrations.py a partir de ../0005_terms_consent.up.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0005_terms_consent.up.sql — durable, append-only LGPD consent to the Solution's
-- terms of use (C6 Termo de Uso de APIs 3.5 / B9, SIN-68743).
--
-- The C6 contract obliges the Desenvolvedor to COLLECT and STORE the user's
-- informed consent to the terms of use. This table is that durable proof: it
-- records WHO (subject) accepted WHICH terms version, WHEN, and through which
-- collection channel (+ optional IP/user-agent evidence), scoped by tenant.
--
-- This is a SEPARATE concern from the PIX Automático mandate tables (pix_rec /
-- pix_cobr): those authorize money movement; this records legal consent to terms.
--
-- APPEND-ONLY by contract: the adapter only ever INSERTs — there is NO UPDATE or
-- DELETE path in application code, so a captured consent is immutable and
-- re-consent produces a new row (the full history is preserved, OWASP A09).
--
-- PII: subject / method_ip / method_user_agent are personal data. They are stored
-- here (that is the point — the durable evidence) but never logged
-- (termsconsent.Record.LogValue redacts them). No secret/credential is stored.
--
-- Portability (same conventions as 0001..0004): TEXT opaque ids, TEXT RFC3339-UTC
-- timestamps, no SQLite-only types/pragmas, so the table ports to Postgres
-- unchanged.
CREATE TABLE IF NOT EXISTS terms_consent (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    subject           TEXT NOT NULL,
    terms_version     TEXT NOT NULL,
    granted_at        TEXT NOT NULL,
    -- collection evidence: channel is always present; ip/user-agent may be empty
    -- for a non-browser channel.
    method_channel    TEXT NOT NULL DEFAULT '',
    method_ip         TEXT NOT NULL DEFAULT '',
    method_user_agent TEXT NOT NULL DEFAULT ''
);

-- Retrieval by (tenant, subject, version), latest-first — the acceptance lookup —
-- and the append-only history for one subject.
CREATE INDEX IF NOT EXISTS ix_terms_consent_lookup
    ON terms_consent (tenant_id, subject, terms_version, granted_at);
