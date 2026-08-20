-- GERADO por scripts/gen-pg-migrations.py a partir de ../0015_account_outbound_delivery.up.sql — NAO EDITE A MAO.
-- Regras: BLOB->BYTEA; *_cents INTEGER->BIGINT. Veja o script para o porque.
-- 0015_account_outbound_delivery.up.sql — the durable per-Conta OUTBOX and the
-- DEAD-LETTER park for "webhook de saída por Conta" (SIN-69491, F1 of SIN-69486,
-- model (b) ADR-0011). This phase attributes an inbound webhook event to its owning
-- Conta SERVER-SIDE and MATERIALISES it for delivery; there is NO network forward yet
-- (that is F2) and the whole surface is DARK behind PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK
-- (default-off), so both tables are inert until the flag turns attribution on.
--
-- WHY two tables: fail-closed attribution (threat model SIN-69489 §6) splits into two
-- terminal outcomes — an event whose owning Conta is known lands on that Conta's
-- outbox (account_outbound_delivery) for F2 to forward; an event whose owner is
-- INDETERMINABLE lands in the dead-letter (account_outbound_dead_letter) for inspection
-- / replay, never forwarded to a guessed Conta and never dropped.
--
-- NOT ENCRYPTED (contrast 0012/0013/0014, which hold secrets and are sealed): neither
-- table carries the HMAC signing secret or the raw event body. They hold only internal
-- opaque identifiers (account_id, tenant_id, tx_id), the dedup event_key, a constant
-- event_type and — for the park — a classified reason. That is enough for F2 to
-- reconcile the authoritative state and build/sign the delivery itself, and enough for
-- an operator to inspect/replay, WITHOUT copying the devedor PII a Pix payload can carry
-- (sin-68744). Keeping payload/PII out of this outbox means it is not a new PII-at-rest
-- surface and needs no envelope encryption.
--
-- IDEMPOTENCY / DEDUP (reuses the inbound event_key, the same key the processed_events
-- anti-replay barrier uses): a redelivered inbound event must not enqueue a duplicate
-- forward, so the outbox is UNIQUE on (account_id, event_key) and the park is UNIQUE on
-- (tenant_id, event_key). The adapter writes with ON CONFLICT DO NOTHING so a duplicate
-- is a silent no-op.
--
-- ISOLATION (A01): the outbox row is keyed by the account_id resolved server-side from
-- the authenticated inbound channel — never anything from the payload. The dead-letter
-- deliberately has NO account_id column: an unattributable event has no known owner, so
-- there is nothing to key it by (and no risk of it being read as "belonging" to a Conta).
--
-- Reversibility: purely additive (two CREATE TABLEs + two indexes); 0015_*.down.sql
-- drops them. Touches no existing table, so rollback is a clean drop + config flip.
--
-- Portability (same conventions as 0001..0014): TEXT opaque ids / event_key /
-- event_type / status / reason and RFC3339-UTC timestamps. No SQLite-only types.

-- The per-Conta outbox: inbound events attributed to a real reseller Conta, pending
-- forward by F2.
CREATE TABLE IF NOT EXISTS account_outbound_delivery (
    id          TEXT NOT NULL,    -- opaque delivery id (PRIMARY KEY)
    account_id  TEXT NOT NULL,    -- owning Conta, resolved SERVER-SIDE (A01 key)
    tenant_id   TEXT NOT NULL,    -- originating tenant (the authenticated inbound channel)
    event_key   TEXT NOT NULL,    -- dedup key (shared with processed_events)
    tx_id       TEXT NOT NULL,    -- referenced charge/session id (may be empty string)
    event_type  TEXT NOT NULL,    -- business event type, e.g. payment.paid
    status      TEXT NOT NULL,    -- lifecycle: 'pending' in F1 (F2 owns further states)
    created_at  TEXT NOT NULL,    -- RFC3339-UTC attribution instant
    PRIMARY KEY (id)
);

-- Idempotency/dedup: one outbox row per (Conta, inbound event). A redelivered event
-- collides here and the adapter's ON CONFLICT DO NOTHING makes it a no-op.
CREATE UNIQUE INDEX IF NOT EXISTS ux_outbound_delivery_account_event
    ON account_outbound_delivery (account_id, event_key);

-- F2's consumer scans pending work per Conta; index the hot (account_id, status) path.
CREATE INDEX IF NOT EXISTS ix_outbound_delivery_account_status
    ON account_outbound_delivery (account_id, status);

-- The dead-letter park: inbound events whose owning Conta could not be determined.
-- No account_id (owner unknown by definition); reason classifies why it was parked.
CREATE TABLE IF NOT EXISTS account_outbound_dead_letter (
    id          TEXT NOT NULL,    -- opaque dead-letter id (PRIMARY KEY)
    tenant_id   TEXT NOT NULL,    -- originating tenant
    event_key   TEXT NOT NULL,    -- dedup key
    tx_id       TEXT NOT NULL,    -- referenced charge/session id (may be empty string)
    event_type  TEXT NOT NULL,    -- business event type
    reason      TEXT NOT NULL,    -- classified cause, e.g. 'unresolvable'
    created_at  TEXT NOT NULL,    -- RFC3339-UTC parking instant
    PRIMARY KEY (id)
);

-- Idempotency: one park row per (tenant, inbound event).
CREATE UNIQUE INDEX IF NOT EXISTS ux_outbound_dead_letter_tenant_event
    ON account_outbound_dead_letter (tenant_id, event_key);
