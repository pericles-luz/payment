-- 0014_account_outbound_webhook.up.sql — durable, account-scoped home for a Conta's
-- single OUTBOUND webhook configuration (SIN-69490, F0 of SIN-69486, model (b)
-- ADR-0011). Config only: this phase persists WHERE a Conta's events will be POSTed
-- (F2) and the HMAC signing secret those deliveries are signed with. There is NO
-- forwarding here (that is F2) and the whole surface is DARK behind the
-- PAYMENT_ACCOUNT_OUTBOUND_WEBHOOK flag (default-off), so this table is inert until
-- an operator turns the console CRUD on.
--
-- WHY: outbound webhooks per Conta (SIN-69485/69486) need durable, encrypted,
-- auditable configuration before any delivery can be built. The board decided one
-- endpoint per Conta in v1 (a simple aggregate), so the table is keyed by account_id
-- with upsert semantics — never a per-Conta collection.
--
-- WHAT: one row per owning Conta (account_id PRIMARY KEY):
--   * url                   — the https delivery endpoint (NON-secret; the operator
--                             sees it on the card to configure their receiver). It is
--                             validated https-only at the boundary AND the domain
--                             (defense-in-depth); the dial-time SSRF enforcement lands
--                             in F2, not here.
--   * signing_secret_sealed — the HMAC signing secret, AES-256-GCM SEALED before it
--                             reaches this column (nonce||ciphertext||tag), never
--                             plaintext. Unlike an account key (a bearer we only ever
--                             VERIFY, so we hash it), this secret must be RECOVERABLE
--                             at delivery time to compute the HMAC, so it is ENCRYPTED,
--                             not hashed — exactly like the bank credential (0012) and
--                             console TOTP (0013) vaults.
--   * enabled               — delivery on/off (F2 consults it; F0 only stores it).
--
-- ENCRYPTED-AT-REST (mirrors migrations 0012/0013): the sealing key is the SAME KEK
-- the bank vault uses (PAYMENT_BANK_VAULT_KEY), held only in the injected cipher and
-- never committed. The seal is additionally BOUND to the row's account_id via
-- secret.OutboundWebhookAAD, so a sealed secret copied to another Conta's row fails
-- to open (defense in depth beyond the row lookup; SIN-69369 pattern). With
-- PAYMENT_BANK_VAULT_KEY unset the wiring never builds this store (no cipher to seal
-- the secret), so the table stays empty and the feature is doubly inert.
--
-- Reversibility: purely additive (CREATE TABLE only); 0014_*.down.sql drops the
-- table. Touches no existing table, so rollback is a clean drop + config flip.
--
-- Portability (same conventions as 0001..0013): TEXT opaque ids / URL / RFC3339-UTC
-- timestamps, BLOB sealed bytes (Postgres: BYTEA), INTEGER boolean (0/1). No
-- SQLite-only types.

CREATE TABLE IF NOT EXISTS account_outbound_webhook (
    account_id            TEXT NOT NULL,    -- owning Conta id; a non-secret identifier
    url                   TEXT NOT NULL,    -- https delivery endpoint; non-secret, rendered back
    signing_secret_sealed BLOB NOT NULL,    -- AES-256-GCM sealed HMAC secret; never plaintext
    enabled               INTEGER NOT NULL, -- 0/1 delivery toggle (F2 consults; F0 stores)
    created_at            TEXT NOT NULL,    -- RFC3339-UTC first-provisioned instant
    updated_at            TEXT NOT NULL,    -- RFC3339-UTC last-write instant
    PRIMARY KEY (account_id)
);
