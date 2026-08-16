-- 0013_console_credential.up.sql — durable, ENCRYPTED-AT-REST home for the
-- self-contained console operator credential and its TOTP replay guard
-- (SIN-69432, follow-up of SIN-69265/ADR-0001 Opção B, umbrella SIN-69118).
--
-- WHY: the console login (username + argon2id password + RFC6238 TOTP) was stored
-- in-process (`consoleauth.MemStore`, cmd/api/main.go), so every restart dropped the
-- provisioned credential and forced the operator to re-run /console/bootstrap with
-- the deploy token. In production (payment.lmhost.com.br, CD auto-restart on deploy)
-- that broke board access on every deploy — unacceptable for a prod admin console.
-- Every other durable aggregate already lives in SQLite; this one lagged behind.
--
-- WHAT: two tables keyed by the operator username (a single fixed operator today —
-- the model is single-username, not multi-operator; keyed by username so the schema
-- does not have to change if that ever relaxes).
--
--   * console_credential  — the provisioned operator credential (survives restart)
--   * console_totp_replay — last consumed TOTP step per subject (single-use guard)
--
-- ENCRYPTED-AT-REST (mirrors the bank secret vault, migration 0012): the TOTP shared
-- secret is the only true secret at rest and is sealed with secret.Seal (AES-256-GCM)
-- BEFORE it reaches its column — totp_secret_sealed holds nonce||ciphertext||tag,
-- never plaintext. The AES key is the SAME KEK the bank vault uses
-- (PAYMENT_BANK_VAULT_KEY), never committed. The password is stored ONLY as its
-- argon2id-encoded hash (already one-way, safe at rest, never the plaintext); the
-- username is a non-secret identifier and stays plaintext. The TOTP step counter is a
-- monotonic integer, not secret.
--
-- ENV-AS-BOOTSTRAP PRESERVED (failure-closed, backward compatible): this migration
-- does NOT provision a credential. First access still runs /console/bootstrap gated
-- by PAYMENT_CONSOLE_BOOTSTRAP_TOKEN; the durable table just makes that one-time
-- provisioning SURVIVE a restart, so the second bootstrap after a restart is refused
-- (credential already present) exactly like within a single process lifetime.
--
-- Reversibility: purely additive (CREATE TABLE only); 0013_*.down.sql drops both
-- tables. Touches no existing table. With PAYMENT_BANK_VAULT_KEY unset the wiring
-- keeps the in-memory console store (no cipher to seal the TOTP secret at rest), so
-- this migration is inert until the durable adapter is switched on.
--
-- Portability (same conventions as 0001..0012): TEXT opaque ids, TEXT RFC3339-UTC
-- timestamps, BLOB sealed bytes (Postgres: BYTEA), INTEGER counter. No SQLite-only
-- types.

CREATE TABLE IF NOT EXISTS console_credential (
    username           TEXT NOT NULL, -- fixed operator login; a non-secret identifier
    password_hash      TEXT NOT NULL, -- argon2id-encoded hash; one-way, never plaintext
    totp_secret_sealed BLOB NOT NULL, -- AES-256-GCM sealed TOTP secret; never plaintext
    updated_at         TEXT NOT NULL, -- RFC3339-UTC last-write instant
    PRIMARY KEY (username)
);

CREATE TABLE IF NOT EXISTS console_totp_replay (
    subject    TEXT NOT NULL,    -- operator username the step was consumed for
    last_step  INTEGER NOT NULL, -- last consumed RFC6238 step; a later login needs step > this
    updated_at TEXT NOT NULL,    -- RFC3339-UTC last-write instant
    PRIMARY KEY (subject)
);
