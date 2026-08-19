-- Reverses 0018. SQLite gained DROP COLUMN in 3.35, but the project's portability
-- convention is the table rebuild, which works on every version and is explicit about
-- what the reverted shape is. Data in the dropped columns is discarded by definition.

CREATE TABLE account_outbound_delivery_old (
    id          TEXT NOT NULL,
    account_id  TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    event_key   TEXT NOT NULL,
    tx_id       TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO account_outbound_delivery_old
    (id, account_id, tenant_id, event_key, tx_id, event_type, status, created_at)
SELECT id, account_id, tenant_id, event_key, tx_id, event_type, status, created_at
FROM account_outbound_delivery;

DROP TABLE account_outbound_delivery;
ALTER TABLE account_outbound_delivery_old RENAME TO account_outbound_delivery;

CREATE UNIQUE INDEX IF NOT EXISTS ux_outbound_delivery_account_event
    ON account_outbound_delivery (account_id, event_key);
CREATE INDEX IF NOT EXISTS ix_outbound_delivery_account_status
    ON account_outbound_delivery (account_id, status);
