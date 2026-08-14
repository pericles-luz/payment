-- 0008_invoices.up.sql — durable, append-only Faturas (invoices) for the metered
-- API consumption of an empresa-cliente (tenant) over a closed billing period.
-- Trilha B of the C6 go-live (SIN-69121 / umbrella SIN-69118).
--
-- A Fatura is a FROZEN SNAPSHOT of the append-only billing_ledger for one tenant
-- over a half-open window [period_start, period_end). Its line totals are the sum
-- of the recorded ledger-entry prices at generation time — NOT a value recomputed
-- from the mutable endpoint_pricing table — so a later price change never rewrites
-- a past invoice and the same window always reproduces the same figures (the
-- authoritative-ledger invariant that billing_ledger already carries).
--
-- account_id is the two-level-tenancy rollup parent (the API user / reseller,
-- e.g. Verz — migration 0007). It is denormalised onto the invoice header so a
-- reseller-level statement can group account -> tenant(empresa-cliente) -> period
-- without re-deriving the account from a mutable tenants.account_id that may be
-- reparented later. NULL/'' means the tenant's self-account (legacy/flat model).
--
-- APPEND-ONLY by contract: application code only ever INSERTs — there is NO UPDATE
-- or DELETE path — so a generated invoice is immutable and regenerating a period
-- produces a NEW row (the full billing history is preserved, OWASP A09). The two
-- tables are written together in one transaction (header + its lines), so a
-- reader never sees a header without its body.
--
-- PII: an invoice carries only tenant/account ids, endpoint names, call counts
-- and money — no personal data, no secret/credential is stored.
--
-- Portability (same conventions as 0001..0007): TEXT opaque ids, TEXT RFC3339-UTC
-- timestamps, INTEGER cents/counts, no SQLite-only types/pragmas, so the tables
-- port to Postgres unchanged.
CREATE TABLE IF NOT EXISTS invoices (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    account_id   TEXT NOT NULL DEFAULT '', -- rollup parent; '' = self-account
    period_start TEXT NOT NULL,            -- inclusive, RFC3339-UTC
    period_end   TEXT NOT NULL,            -- exclusive, RFC3339-UTC
    total_calls  INTEGER NOT NULL,
    total_cents  INTEGER NOT NULL,
    generated_at TEXT NOT NULL,
    CONSTRAINT fk_invoice_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id)
);

-- One row per billed endpoint on an invoice. seq preserves the document order the
-- header was generated with (endpoints sorted); the PK (invoice_id, seq) makes the
-- body rows unique and their read order deterministic without a separate index.
CREATE TABLE IF NOT EXISTS invoice_items (
    invoice_id     TEXT NOT NULL,
    seq            INTEGER NOT NULL,
    endpoint       TEXT NOT NULL,
    calls          INTEGER NOT NULL,
    subtotal_cents INTEGER NOT NULL,
    PRIMARY KEY (invoice_id, seq),
    CONSTRAINT fk_item_invoice FOREIGN KEY (invoice_id) REFERENCES invoices (id)
);

-- Tenant-scoped listing, newest-first (the console "Faturas" screen and the
-- per-tenant history read this path).
CREATE INDEX IF NOT EXISTS ix_invoices_tenant ON invoices (tenant_id, generated_at);
