-- GERADO por scripts/gen-pg-migrations.py a partir de ../0006_pii_access_log.up.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0006_pii_access_log.up.sql — LGPD / Decreto 8.771/2016 art.13 register of READ
-- access to a titular's personal data in the data plane (Termo C6 B10-v; ADR-0008,
-- SIN-68748; design SIN-68744).
--
-- Distinct from audit_log (0002/0003): audit_log is the closed vocabulary of
-- privileged MUTATIONS (B10-iv). This table is the far-higher-cardinality inventory
-- of READS that resolved and exposed a natural person's PII — who read, WHICH
-- subject (a NON-reversible pseudonym), which object, when and for how long. Keeping
-- them apart preserves each trail's semantics, cost/retention profile and
-- tamper-evidence (ADR-0008 §3).
--
-- MINIMISATION (ADR-0008 §4): this table NEVER stores devedor_doc/devedor_nome, a
-- name or an address in clear. subject_ref is an HMAC-SHA256 pseudonym of the
-- normalised document (or an opaque business id) — mirroring access.Entry, which
-- has no plaintext-PII field by construction. So this A09/art.13 mitigation does not
-- itself become a new LGPD leak surface or a second copy of PII to erase.
--
-- Append-only by contract: the adapter only ever INSERTs. The single DELETE path is
-- the retention purge (PurgePIIAccessBefore) — the bounded, minimising expiry of old
-- entries — never an UPDATE, never a targeted delete.
--
-- responsible is derived SERVER-SIDE (ADR-0008 §2): tenant_id + the non-secret
-- credential/client_id, plus operator_id when the read came from the admin/console
-- plane. Never a client-asserted identity, never the credential secret (threat C1/C4).
--
-- Portability (same conventions as 0001/0002/0004): TEXT opaque ids, TEXT
-- RFC3339-UTC timestamps, INTEGER duration/counters (BIGINT in Postgres). No
-- SQLite-only types, so the schema ports to Postgres unchanged. Created with
-- IF NOT EXISTS so the migration is safe to re-run (the ledger also skips it).
CREATE TABLE IF NOT EXISTS pii_access_log (
    id          TEXT PRIMARY KEY,
    at          TEXT NOT NULL,               -- RFC3339-UTC instant the read began
    duration_ms INTEGER NOT NULL DEFAULT 0,  -- art.13 "duração" of the read, whole ms
    tenant_id   TEXT NOT NULL,               -- responsible: the scoping/authenticated tenant
    client_id   TEXT NOT NULL DEFAULT '',    -- responsible: non-secret credential/client id (never the secret)
    operator_id TEXT NOT NULL DEFAULT '',    -- responsible: admin/console operator (server-derived), '' for a data-plane read
    subject_ref TEXT NOT NULL,               -- pseudonymous titular ref (HMAC-SHA256 or opaque id) — NEVER plaintext PII
    object      TEXT NOT NULL,               -- accessed object as type:id (e.g. 'rec:{idRec}')
    action      TEXT NOT NULL                -- closed read vocabulary ('pii.read.rec', ...)
);

-- Forensic / LGPD queries: "what did this tenant read, in time order" and "every
-- access to THIS titular, in time order" (a data-subject request over the pseudonym).
CREATE INDEX IF NOT EXISTS ix_pii_access_tenant_at ON pii_access_log (tenant_id, at);
CREATE INDEX IF NOT EXISTS ix_pii_access_subject_at ON pii_access_log (subject_ref, at);
-- Retention purge scans by time; index supports the bounded expiry sweep.
CREATE INDEX IF NOT EXISTS ix_pii_access_at ON pii_access_log (at);
