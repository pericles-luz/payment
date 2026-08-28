-- Reverses 0019. SQLite gained DROP COLUMN in 3.35, but the project's portability
-- convention is the table rebuild, which works on every version and is explicit about
-- what the reverted shape is. The QR-journey binding is discarded by definition: a
-- mandate reverted to the 0004 shape can no longer have its composite QR re-composed.

CREATE TABLE pix_rec_old (
    id_rec        TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    bank_id       TEXT NOT NULL,
    contrato      TEXT NOT NULL,
    devedor_doc   TEXT NOT NULL,
    devedor_nome  TEXT NOT NULL,
    data_inicial  TEXT NOT NULL,
    periodicidade TEXT NOT NULL,
    valor_cents   INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id_rec)
);

INSERT INTO pix_rec_old
    (id_rec, tenant_id, bank_id, contrato, devedor_doc, devedor_nome,
     data_inicial, periodicidade, valor_cents, status, created_at, updated_at)
SELECT id_rec, tenant_id, bank_id, contrato, devedor_doc, devedor_nome,
       data_inicial, periodicidade, valor_cents, status, created_at, updated_at
FROM pix_rec;

DROP TABLE pix_rec;
ALTER TABLE pix_rec_old RENAME TO pix_rec;

CREATE INDEX IF NOT EXISTS ix_pix_rec_tenant ON pix_rec (tenant_id, created_at);
