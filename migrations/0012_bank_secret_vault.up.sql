-- 0012_bank_secret_vault.up.sql — durable, ENCRYPTED-AT-REST home for the two bank
-- secret vaults (SIN-69366, umbrella SIN-69118). Exposed by the CEO's go-live
-- question: today the OAuth credential vault (`secret.Store`) and the mTLS
-- certificate vault (`secret.CertStore`) are in-PROCESS maps seeded from env at
-- boot, so anything a client configures at runtime (C6 credential + cert) is LOST on
-- restart. Every other durable aggregate (Conta/tenant/account-key/ledger/faturas/
-- auditoria) already lives in SQLite; these two lagged behind (`secret/cert.go:16`,
-- `secret/crypto.go:17`).
--
-- WHAT: two tables, each keyed by the composite (tenant_id, bank_id) pair — the SAME
-- key the in-memory vaults use (ADR-0007 T2: bank_id subdivides, never relaxes, the
-- tenant scope). They back a SQLite adapter that satisfies the SAME hexagonal ports
-- as the in-memory adapter (ports.CredentialStore/Writer/Deleter/CreditorKeyWriter
-- and ports.BankCertificate{Writer,Reader,Deleter}), so wiring swaps one for the
-- other and the use-cases never know (SIN-69366 scope).
--
-- ENCRYPTED-AT-REST (threat C1/C4, ADR-0007): every SECRET value is sealed with
-- secret.Seal (AES-256-GCM, crypto.go) BEFORE it reaches a column — the durable
-- column holds nonce||ciphertext||tag, never plaintext. The AES key is a KEK loaded
-- from env (PAYMENT_BANK_VAULT_KEY), never committed. Non-secret identifiers stay
-- plaintext: client_id is an identity (logged un-redacted today), and a leaf
-- certificate is public by definition.
--
--   * bank_credentials.secret_sealed        — sealed OAuth client secret (rotation)
--   * bank_credentials.creditor_key_sealed   — sealed PIX creditor key (routing)
--   * bank_certificates.key_pem_sealed       — sealed mTLS private key (write-only)
--
-- WRITE-ONLY private key: bank_certificates.key_pem_sealed is only ever written and
-- used to build the TLS transport — it is NEVER returned on a read path (the reader
-- surfaces only public metadata re-derived from cert_pem), preserving the CertStore
-- posture.
--
-- ENV-AS-BOOTSTRAP, DB-AS-DURABLE (backward compatible): the adapter's Seed step
-- inserts an env-provided credential ONLY when its (tenant, bank) row is absent
-- (INSERT ... ON CONFLICT DO NOTHING), so env seeds a fresh deployment once and every
-- runtime edit thereafter is the durable source of truth — an env value never
-- silently overwrites a client's runtime change on the next boot.
--
-- Reversibility: purely additive (CREATE TABLE + CREATE INDEX); 0012_*.down.sql drops
-- them index-before-table. Touches no existing table. With PAYMENT_BANK_VAULT_KEY
-- unset the wiring keeps the in-memory vaults, so this migration is inert until the
-- durable adapter is switched on.
--
-- Portability (same conventions as 0001..0011): TEXT opaque ids, TEXT RFC3339-UTC
-- timestamps, BLOB sealed bytes (Postgres: BYTEA). No SQLite-only types.

CREATE TABLE IF NOT EXISTS bank_credentials (
    tenant_id           TEXT NOT NULL,
    bank_id             TEXT NOT NULL,
    client_id           TEXT NOT NULL, -- OAuth client id; an identifier, not a secret
    secret_sealed       BLOB NOT NULL, -- AES-256-GCM sealed OAuth secret; never plaintext
    creditor_key_sealed BLOB NULL,     -- AES-256-GCM sealed PIX creditor key; NULL until set
    updated_at          TEXT NOT NULL, -- RFC3339-UTC last-write instant
    PRIMARY KEY (tenant_id, bank_id)
);

CREATE TABLE IF NOT EXISTS bank_certificates (
    tenant_id     TEXT NOT NULL,
    bank_id       TEXT NOT NULL,
    cert_pem      TEXT NOT NULL, -- PUBLIC leaf certificate (PEM); safe in plaintext
    key_pem_sealed BLOB NOT NULL, -- AES-256-GCM sealed mTLS private key; WRITE-ONLY, never read back
    updated_at    TEXT NOT NULL, -- RFC3339-UTC last-write instant
    PRIMARY KEY (tenant_id, bank_id)
);
