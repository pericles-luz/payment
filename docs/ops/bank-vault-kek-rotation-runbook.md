# Runbook — Rotating the Bank Secret Vault KEK (`PAYMENT_BANK_VAULT_KEY`)

**Scope:** the durable, encrypted-at-rest bank credential/certificate vault
(SIN-69366; migration 0012, tables `bank_credentials` and `bank_certificates`).
Hardening follow-up: SIN-69369.

**Audience:** operator / on-call performing a key rotation, plus the SecEng
reviewer signing off on it.

---

## 1. What is encrypted, and how

Every bank OAuth secret, PIX creditor key, and mTLS private key is sealed with
**AES-256-GCM** before it touches a column (`*_sealed` columns hold
`nonce||ciphertext||tag`, never plaintext). The AES-256 key is a **KEK**
(key-encryption key) loaded ONLY from the environment variable
`PAYMENT_BANK_VAULT_KEY` (64 hex chars = 32 bytes). It is never written to disk,
never logged, and held only in-process.

Since SIN-69369 each blob is additionally **cryptographically bound to its row**
via GCM *additional authenticated data* (AAD): the AAD is
`RowAAD(tenant_id, bank_id)` (a length-prefixed, domain-tagged encoding of the
row's own key columns). The AAD is not secret and not stored — it is
reconstructed from the row on read. Consequence: a ciphertext copied into a
different `(tenant_id, bank_id)` row **fails to decrypt** (defense in depth
against confused-deputy / row-relocation; ADR-0007 C1/C4).

## 2. The fail-closed caveat (READ FIRST)

There is **no plaintext copy** of any secret. If you change
`PAYMENT_BANK_VAULT_KEY` **without re-encrypting the rows first**, every existing
row becomes **permanently undecryptable** — `Open` fails GCM authentication and
the affected credential/certificate reads fail closed (this is correct: a wrong
key must never silently succeed, and there is no downgrade path). The service
keeps booting, but any tenant whose secret lived only in the vault can no longer
transact until its credential is re-provisioned.

**Therefore: never rotate the KEK by editing the env var alone. Always run the
re-seal procedure below.** The same procedure performs the one-time AAD migration
for any environment that already held vault rows before SIN-69369 (those rows
were sealed with a nil AAD; the re-seal upgrades them transparently — see §5).

## 3. Prerequisites

- The new 32-byte KEK, hex-encoded (64 chars). Generate with a CSPRNG, e.g.
  `openssl rand -hex 32`. Store it in the secret manager the same way as the
  current key. **Do not** paste keys into shell history or tickets.
- The **current** KEK value (the one that sealed the live rows).
- A **backup of the SQLite database file** (`PAYMENT_DB_PATH`) taken with the
  service stopped. This is the rollback anchor (§6).
- A maintenance window: the re-seal runs offline (service stopped, or a moment
  when no writes hit the vault). Reads/writes during the rewrite are not
  coordinated with it.

## 4. Procedure

1. **Announce** the maintenance window and **stop** the `api` process (or drain
   it so no vault writes occur).
2. **Back up** the database file:
   `cp "$PAYMENT_DB_PATH" "$PAYMENT_DB_PATH.pre-rotate.$(date -u +%Y%m%dT%H%M%SZ)"`
   (do this while the service is stopped so the file is consistent).
3. **Run the re-seal** — decrypts every row with the OLD key and re-encrypts with
   the NEW key. Both tables (credentials AND certificates) are rewritten inside a
   **single transaction** — all-or-nothing across the whole vault (SIN-69372):

   ```sh
   PAYMENT_DB_PATH=/data/payment.db \
   PAYMENT_BANK_VAULT_KEY=<NEW 64-hex key> \
   PAYMENT_BANK_VAULT_KEY_PREVIOUS=<OLD 64-hex key> \
     go run ./cmd/vault-reseal        # or the built vault-reseal binary
   ```

   It logs the number of credential and certificate rows rewritten. On **any**
   error it commits nothing (the vault stays fully readable with the OLD key);
   fix the cause and re-run.
4. **Point the service at the new key:** set `PAYMENT_BANK_VAULT_KEY` to the NEW
   value for the `api` process and **clear** `PAYMENT_BANK_VAULT_KEY_PREVIOUS`
   (the running service never reads it — it is only for the re-seal tool).
5. **Start** the `api` process. Smoke-test: read back one credential and one
   certificate per active tenant (e.g. the admin/console cert card and a bank
   call). A successful read proves the row decrypts under the new key.
6. **Retire the old key** from the secret manager once the smoke test passes and
   the backup retention window has elapsed. Keep the backup until you are
   confident the rotation is stable.

## 5. AAD migration (one-time, pre-SIN-69369 rows only)

Rows sealed before SIN-69369 used a nil AAD and will not open on the new
row-bound read path. The re-seal tool detects this: it first tries the
row-bound `Open`, then falls back to the legacy nil-AAD `Open`, and always
**re-seals with the row-bound AAD**. So running the procedure in §4 **once** —
even with `PAYMENT_BANK_VAULT_KEY_PREVIOUS` set equal to the current key (a
same-key re-seal) — upgrades every legacy blob to the bound form. After that, all
reads are row-bound. The legacy fallback lives ONLY in the offline tool, never on
the hot read path, so a genuine authentication failure at runtime stays fatal.

> If the environment was first provisioned on or after SIN-69369, there are no
> legacy rows and this section does not apply.

## 6. Rollback

- **Re-seal failed / aborted:** nothing was committed — the tool rewrites BOTH
  the credential and certificate tables in one transaction (SIN-69372), so a
  failure anywhere (including a certificate error after the credential rows were
  already staged) rolls the whole rotation back. The vault stays fully readable
  with the OLD key, never half-rotated. Restore nothing; just fix the cause and
  re-run with the same `(new, previous)` pair, or restart the service with the OLD
  `PAYMENT_BANK_VAULT_KEY`.
- **Re-seal succeeded but the new key is wrong/lost after cut-over:** stop the
  service, restore the pre-rotate backup from step 2 over `PAYMENT_DB_PATH`, set
  `PAYMENT_BANK_VAULT_KEY` back to the OLD value, and start. You are back to the
  pre-rotation state; investigate before retrying.
- Running the re-seal **twice with the same (new, previous) pair** fails loudly
  on the second pass (the rows are already under the new key, which the old key
  cannot open) rather than corrupting data — safe to attempt.

## 7. Operational safety notes

- Keys are never logged by `vault-reseal` or the `api` process; keep them out of
  shell history (prefer an env file with `chmod 600`, or the secret manager's
  injection) and out of tickets/PRs.
- The re-seal is idempotent in effect but not a routine job — run it only for a
  deliberate rotation or the one-time AAD migration.
- `PAYMENT_BANK_VAULT_KEY` and `PAYMENT_BANK_VAULT_KEY_PREVIOUS` must differ for a
  real rotation; the tool refuses identical values *unless* you are doing the
  same-key AAD migration (§5), in which case pass the same value to both — the
  tool treats equal keys as the migration case and still rewrites the AAD.
```
