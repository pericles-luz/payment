-- GERADO por scripts/gen-pg-migrations.py a partir de ../0020_nfse.up.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0020_nfse.up.sql — emissão de NFS-e (padrão nacional / ADN) pelo gateway.
--
-- WHY: the NFS-e emitter that lived in go-mei-das (internal/nfse) moved here so
-- every product (catalogo, go-mei-das) emits through one API. Emission is a
-- counted operation (billing_ledger, endpoint "nfse.emit"), free while no price
-- is configured.
--
-- WHAT:
--   nfse_emissions      one row per emission attempt, tenant-scoped. A pending
--                       row is the idempotency reservation (Idempotency-Key);
--                       the partial unique index is the anti-double-emission
--                       anchor. number is pinned on the pending row before the
--                       DPS is transmitted, so a takeover of a crashed attempt
--                       re-sends the SAME DPS. nfse_xml keeps the authorised
--                       document; danfse_pdf caches the PDF fetched from the ADN.
--   nfse_a1_certs       the PUBLIC chain + non-secret metadata of each A1
--                       certificate (company_id = tenant "_" cnpj). The private
--                       key never touches this database: it lives as a
--                       non-exportable key in Vault transit (FiscalSigner).
--                       cnpj_hash, never the raw document.
--   nfse_dps_sequences  nDPS per (emitter CNPJ, série). The numbering belongs to
--                       the gateway because several products emit for the same
--                       CNPJ. Incremented with an atomic upsert (... RETURNING).
--
-- PII: tomador_doc / tomador_nome may be a natural person (CPF). They are also
-- inside nfse_xml by force of the fiscal document; reads are tenant-scoped.
--
-- Reversibility: 0020_nfse.down.sql drops the three tables. Dropping
-- nfse_a1_certs loses only public metadata (no signing capability is erased —
-- that is the Vault key deletion). Dropping nfse_dps_sequences makes numbering
-- restart: pick a new série before re-applying.
--
-- Portability (same conventions as 0001_init): TEXT ids and RFC3339-UTC
-- timestamps, BLOB for binary (BYTEA in pg), *_cents INTEGER (BIGINT in pg).

CREATE TABLE IF NOT EXISTS nfse_emissions (
    id                  TEXT NOT NULL PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    idempotency_key     TEXT NOT NULL DEFAULT '',
    emitter_cnpj        TEXT NOT NULL,
    competencia_year    INTEGER NOT NULL DEFAULT 0,
    competencia_month   INTEGER NOT NULL DEFAULT 0,
    competencia_day     INTEGER NOT NULL DEFAULT 0,  -- 0 = the month (dCompet on day 1)
    service_value_cents BIGINT NOT NULL DEFAULT 0,
    series              TEXT NOT NULL DEFAULT '',
    number              TEXT NOT NULL DEFAULT '',
    tomador_doc         TEXT NOT NULL DEFAULT '',
    tomador_nome        TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL,
    chave_acesso        TEXT NOT NULL DEFAULT '',
    nfse_number         TEXT NOT NULL DEFAULT '',
    dps_id              TEXT NOT NULL DEFAULT '',
    rejection_code      TEXT NOT NULL DEFAULT '',
    rejection_message   TEXT NOT NULL DEFAULT '',
    nfse_xml            BYTEA,
    danfse_pdf          BYTEA,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_nfse_emissions_idem
    ON nfse_emissions (tenant_id, idempotency_key) WHERE idempotency_key <> '';
CREATE INDEX IF NOT EXISTS ix_nfse_emissions_tenant ON nfse_emissions (tenant_id, created_at);

CREATE TABLE IF NOT EXISTS nfse_a1_certs (
    company_id TEXT NOT NULL PRIMARY KEY,
    serial     TEXT NOT NULL,
    subject    TEXT NOT NULL DEFAULT '',
    not_after  TEXT NOT NULL,
    cnpj_hash  TEXT NOT NULL,
    chain_pem  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_nfse_a1_certs_not_after ON nfse_a1_certs (not_after);

CREATE TABLE IF NOT EXISTS nfse_dps_sequences (
    emitter_cnpj TEXT NOT NULL,
    series       TEXT NOT NULL,
    last_number  BIGINT NOT NULL,
    PRIMARY KEY (emitter_cnpj, series)
);
