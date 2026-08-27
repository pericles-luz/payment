# Payment receptor — staging deploy runbook (one-time VPS bootstrap)

> **Audience:** the CEO/operator, run **once** on the VPS. After this, every deploy
> is automated by `.github/workflows/cd-stg.yml` (build → preflight → ship → restart
> → smoke).
> No agent ever runs a command on the VPS. See ADR
> [`docs/security/adr-0006-payment-staging-deploy.md`](../security/adr-0006-payment-staging-deploy.md).

- **Service:** payment receptor, single Go binary `cmd/api`.
- **Listens:** `:8080`, `/healthz`, published at `payment.lmhost.com.br`.
- **Host:** `pre-prod`, SSH on `201.23.79.48:22`, behind the Caddy balancer
  ([`cutover-lmhost.md`](cutover-lmhost.md), 21/08/2026). Was `143.198.66.140` behind
  HAProxy before the cutover.
- **Decision:** durable CD, Opção A ([SIN-65858](/SIN/issues/SIN-65858), [SIN-65900](/SIN/issues/SIN-65900)).

> 🔐 **No secret is ever pasted into a Paperclip thread.** The C6 client cert/key,
> the deploy SSH private key, and the `.env.stg` values live only on the VPS or in
> GitHub Actions secrets — never in repo, comment, PR, or issue.

---

## 0. Prerequisites (on your workstation)

- SSH access to the VPS as a sudo-capable user (to perform this bootstrap).
- `ssh-keygen`, `ssh-keyscan` available locally.

---

## 1. Create the non-root service user and layout

Run on the VPS as a sudo-capable user:

```bash
# Dedicated, non-login service account (no shell needed for the service itself;
# the deploy wrapper is invoked over SSH with a forced command).
sudo useradd --system --create-home --shell /bin/bash payment

# Directory layout, owned by the service account.
sudo install -d -o payment -g payment -m 0755 /opt/payment
sudo install -d -o payment -g payment -m 0755 /opt/payment/bin
sudo install -d -o payment -g payment -m 0755 /opt/payment/incoming
sudo install -d -o payment -g payment -m 0700 /opt/payment/c6   # holds 0600 cert/key

# Whatever the account's home turned out to be, WRITE IT DOWN — §5b installs the CD
# key relative to it, and getting it wrong fails silently (§11).
getent passwd payment | cut -d: -f6
```

> `--create-home` on a `--system` account gives `/home/payment` on Ubuntu. A host
> provisioned differently — created without `-m`, or with `--home-dir /opt/payment` so
> the account lives inside its own install tree — will have a different home. Both are
> fine; what is **not** fine is assuming which one you have. `pre-prod` is the second
> shape (`/opt/payment`).

---

## 2. Install the deploy wrapper

Copy `deploy/scripts/payment-deploy.sh` from the repo to the VPS, then:

```bash
sudo install -o payment -g payment -m 0755 \
  payment-deploy.sh /opt/payment/bin/payment-deploy.sh
```

The wrapper accepts **only** the `deploy` (and read-only `preflight`) verb; any
other command over the deploy key is rejected non-zero (no arbitrary shell).

---

## 3. Install the systemd unit

Copy `deploy/systemd/payment-api.service` to the VPS, then:

```bash
sudo install -o root -g root -m 0644 \
  payment-api.service /etc/systemd/system/payment-api.service
sudo systemctl daemon-reload
sudo systemctl enable payment-api      # start on boot (don't start yet — env+binary first)
```

---

## 4. Single scoped NOPASSWD sudoers entry

The service account may restart **only** its own unit — nothing else:

```bash
echo 'payment ALL=(root) NOPASSWD: /usr/bin/systemctl restart payment-api' \
  | sudo tee /etc/sudoers.d/payment-api
sudo chmod 0440 /etc/sudoers.d/payment-api
sudo visudo -c                          # validate syntax before trusting it
```

> The path must match `SYSTEMCTL` in `payment-deploy.sh` (`/usr/bin/systemctl`).
> Verify with `command -v systemctl`; if it differs, fix the sudoers line to match.

---

## 5. Authorize the CD deploy key (locked to the wrapper)

### 5a. Generate the CD keypair (on your workstation, NOT the VPS)

```bash
ssh-keygen -t ed25519 -f payment-cd -C payment-cd -N ''
# → payment-cd (private)  and  payment-cd.pub (public)
```

### 5b. Authorize the PUBLIC key on the VPS, pinned to the wrapper

> **Derive the home directory — never assume `/home/payment`.** `sshd` resolves
> `AuthorizedKeysFile .ssh/authorized_keys` **relative to the account's home**, and
> `payment` is a *system* account whose home depends on how it was created:
> `/home/payment` when added with `useradd -m`, but `/opt/payment` on a host where it
> was created alongside the install tree. Writing the key to the wrong path fails
> **silently** — `sshd` simply finds no `authorized_keys`, the client exhausts its
> identities, and the only trace is `Connection closed … [preauth]` with **no**
> `Failed publickey` line naming a fingerprint. See §11.

The `command=` forces every connection through the wrapper:

```bash
HOME_DIR="$(getent passwd payment | cut -d: -f6)"   # do NOT hardcode this
[ -n "$HOME_DIR" ] || { echo "user 'payment' does not exist"; exit 1; }

sudo install -d -o payment -g payment -m 0700 "$HOME_DIR/.ssh"
PUB="$(cat payment-cd.pub)"   # the public key you just generated
printf 'command="/opt/payment/bin/payment-deploy.sh",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding %s\n' \
  "$PUB" | sudo -u payment tee -a "$HOME_DIR/.ssh/authorized_keys"
sudo -u payment chmod 0600 "$HOME_DIR/.ssh/authorized_keys"
```

Confirm the file is where `sshd` will actually look for it, and that `$HOME_DIR`
itself is not group/world-writable (`StrictModes yes` refuses the key otherwise):

```bash
sudo sshd -T | grep -i '^authorizedkeysfile'        # → .ssh/authorized_keys …
sudo ssh-keygen -lf "$HOME_DIR/.ssh/authorized_keys"
stat -c '%A %U:%G %n' "$HOME_DIR"                   # → drwxr-xr-x or drwx------
```

> A forced `command=` intercepts **every** connection on this key — there is **no
> scp/SFTP exemption**. So the workflow does not scp: it opens one ssh session
> running the `deploy` verb and streams the binary into the wrapper on **stdin**.
> The wrapper reads stdin to `/opt/payment/incoming/payment-api`, validates it
> (non-empty + ELF), then atomically installs + restarts. `SSH_ORIGINAL_COMMAND`
> is exactly `deploy`, so the allow-list matches; the key can run **only** this
> wrapper (anything else — including a literal `scp …` — is rejected non-zero).

### 5c. The PRIVATE key becomes the `PAYMENT_STG_SSH_KEY` GitHub secret

Keep `payment-cd` (private) **off the VPS and out of any thread**. It goes into
GitHub Actions secrets in step 7. Delete your local copies once the secrets are set.

---

## 6. Capture the VPS host key (no TOFU)

The workflow pins `known_hosts`, so capture it now:

```bash
ssh-keyscan -t ed25519 "$STG_HOST"
# → <host> ssh-ed25519 AAAA...   (one line)
```

That exact line is the `PAYMENT_STG_HOST_KEY` secret. It must be captured against the
**same** address that goes into `PAYMENT_STG_HOST` — the workflow runs with
`StrictHostKeyChecking=yes`, so a pin taken from a different address fails the
handshake before authentication is even attempted.

---

## 7. Set the GitHub Actions secrets (UPSTREAM repo `pericles-luz/payment`)

The CD job is owner-gated to `pericles-luz`, so the secrets live on the **upstream**
repo (the fork has none and the job is a no-op there). Names used by `cd-stg.yml`:

| Secret | Value |
|--------|-------|
| `PAYMENT_STG_SSH_KEY` | the **private** `payment-cd` key (full PEM, including header/footer) |
| `PAYMENT_STG_HOST` | SSH address of the deploy target — **`201.23.79.48` (`pre-prod`) since the lmhost cutover of 21/08/2026**; was `143.198.66.140` before it |
| `PAYMENT_STG_USER` | `payment` |
| `PAYMENT_STG_HOST_KEY` | the `ssh-keyscan` line from step 6, captured against that same address (no TOFU) |
| `PAYMENT_STG_SMOKE_URL` | `https://payment.lmhost.com.br` (the workflow appends `/healthz`) |

> `PAYMENT_STG_HOST` is the **SSH** address and is not the address that serves the
> site: `pre-prod` has no public IP on an interface, it is per-port NAT with only 22
> forwarded, and HTTPS arrives through the Caddy balancer. So `PAYMENT_STG_HOST` and
> `PAYMENT_STG_SMOKE_URL` legitimately point at different places — see
> [`cutover-lmhost.md`](cutover-lmhost.md).

```bash
# example with gh CLI (run where the private key file lives):
STG_HOST='201.23.79.48'    # the CURRENT deploy target; confirm before running
gh secret set PAYMENT_STG_SSH_KEY   --repo pericles-luz/payment < payment-cd
gh secret set PAYMENT_STG_HOST      --repo pericles-luz/payment --body "$STG_HOST"
gh secret set PAYMENT_STG_USER      --repo pericles-luz/payment --body 'payment'
gh secret set PAYMENT_STG_HOST_KEY  --repo pericles-luz/payment --body "$(ssh-keyscan -t ed25519 "$STG_HOST" 2>/dev/null)"
gh secret set PAYMENT_STG_SMOKE_URL --repo pericles-luz/payment --body 'https://payment.lmhost.com.br'
```

> Moving the deploy target means updating **four** things together: the
> `authorized_keys` on the new host (§5b — mind the home directory), `PAYMENT_STG_HOST`,
> `PAYMENT_STG_HOST_KEY` and, if the account differs, `PAYMENT_STG_USER`. Updating only
> some of them is what broke the CD for six days after the lmhost cutover (§11).

After setting the secrets, securely delete your local `payment-cd` / `payment-cd.pub`.

---

## 8. Write `/opt/payment/.env.stg`

> ⚠️ **`EnvironmentFile` is `KEY=VALUE` only — NOT a shell.** Do **not** write
> `export KEY=value`, do **not** quote or use `$VAR`. A line `export PAYMENT_HTTP_ADDR=:8080`
> makes the key literally `export PAYMENT_HTTP_ADDR`, which the app never reads.
> This exact gotcha bit crm. Bare `KEY=value` pairs only.

Create the file as `payment`, mode 0640:

```bash
sudo -u payment tee /opt/payment/.env.stg >/dev/null <<'EOF'
PAYMENT_HTTP_ADDR=:8080
PAYMENT_DB_PATH=/opt/payment/payment.db

# Per-tenant webhook ref → tenant id (capability URL). Replace with the real
# 43-char base64url ref and the 32-char tenant id.
PAYMENT_WEBHOOK_REFS=REPLACE-ref:REPLACE-tenantId

# C6 bank adapter (homologação). Endpoints MUST be https:// (the adapter rejects
# http and fails the boot closed). Empty BaseURL ⇒ in-memory stub (do NOT use in stg).
PAYMENT_C6_BASE_URL=https://REPLACE-c6-base
PAYMENT_C6_TOKEN_URL=https://REPLACE-c6-token
# LEAVE EMPTY. Setting an explicit OAuth2 scope makes C6's /v1/auth/ reply
# 400/invalid_request; omitting it returns 200 with the credential's full scopes.
# Do NOT put a placeholder value here — empty is the working config (SIN-65917).
PAYMENT_C6_SCOPE=

# Per-tenant, per-bank credentials. CANONICAL form is 4-field
# "tenant:bank:client_id:secret,..." (the bank slug — e.g. `c6` — sits BEFORE the
# client_id; client_id is cross-checked against the webhook body). Real values
# from the secret manager. The secret is the greedy ':'-tolerant tail, so a secret
# that itself contains ':' is preserved verbatim.
#
# ⚠️ MIGRATION (SIN-66015 / ADR-0007): the legacy 3-field form
# "tenant:client_id:secret" is still accepted and defaults the bank to `c6`, BUT a
# legacy secret that contains a ':' is AMBIGUOUS — it parses as the 4-field form
# (the client_id is read as the bank slug). That entry fails CLOSED (orphan slot ⇒
# no token minted ⇒ no leak), but silently. ALWAYS write the explicit 4-field form
# with `c6` for C6 tenants so there is no ambiguity:
#   PAYMENT_BANK_CREDS=REPLACE-tenantId:c6:REPLACE-c6-client:REPLACE-c6-secret
# Verify after start that the startup log lists exactly the (tenant, bank) pairs
# you expect (see §9) — an unexpected pair means a misparse to fix before traffic.
PAYMENT_BANK_CREDS=REPLACE-tenantId:c6:REPLACE-c6-client:REPLACE-c6-secret

# Per-tenant PIX creditor key (chave do recebedor): "tenant:creditorKey,...".
# SEPARATE var from PAYMENT_BANK_CREDS (a PIX key may contain ':'; split is on the
# first ':' only). This is where the `chave` lives — NOT in PAYMENT_BANK_CREDS.
# Consumed by the cob (PUT /v2/pix/cob) and by cmd/register-webhook.
PAYMENT_BANK_CREDITOR_KEYS=REPLACE-tenantId:REPLACE-recebedor@pix.example

# mTLS client cert/key: FILE PATHS to 0600 files owned by `payment` (NEVER inline
# the bytes — threat C1). Provisioned per SIN-65806.
PAYMENT_C6_CLIENT_CERT=/opt/payment/c6/client.crt
PAYMENT_C6_CLIENT_KEY=/opt/payment/c6/client.key
EOF
sudo chmod 0640 /opt/payment/.env.stg
sudo chown payment:payment /opt/payment/.env.stg
```

Install the C6 cert/key as 0600 files owned by `payment` (bytes provisioned per
[SIN-65806](/SIN/issues/SIN-65806) — never pasted into a thread):

```bash
sudo install -o payment -g payment -m 0600 /dev/stdin /opt/payment/c6/client.crt < client.crt
sudo install -o payment -g payment -m 0600 /dev/stdin /opt/payment/c6/client.key < client.key
```

---

## 9. First start and verify

```bash
sudo systemctl start payment-api
sudo systemctl status payment-api --no-pager
curl -fsS http://127.0.0.1:8080/healthz   # expect {"status":"ok","version":...,"commit":...}
```

**Confirm the loaded bank credentials (SIN-66015).** On startup the service logs
one `loaded bank credentials` line at info level listing the non-secret
`(tenant, bank)` pairs it parsed (only the tenant id and bank slug — never the
client_id, secret, or creditor key). Confirm it matches what you configured:

```bash
sudo journalctl -u payment-api --no-pager | grep "loaded bank credentials" | tail -1
# expect e.g. count=1 ... tenant_bank_pairs="[REPLACE-tenantId/c6]"
```

If a pair you did NOT configure appears (e.g. a "bank" that is actually a
client_id), a legacy colon-bearing secret misparsed — fix the entry to the
explicit 4-field `tenant:c6:client:secret` form (see §8) and restart before
routing traffic. `count=0` means no credentials were parsed at all.

From here, pushes to upstream `main` that pass `CI` auto-deploy via `cd-stg.yml`,
or trigger a manual deploy from the Actions tab (`workflow_dispatch`).

---

## 9.1 Bootstrap the tenant (REQUIRED on every fresh DB) ⚠️

> 🪤 **Gotcha that recurs on every new deploy.** The service comes up with an
> **empty SQLite DB** (`PAYMENT_DB_PATH=/opt/payment/payment.db`). The `.env.stg`
> already references a `tenantId` in `PAYMENT_WEBHOOK_REFS` /
> `PAYMENT_BANK_CREDS` / `PAYMENT_BANK_CREDITOR_KEYS`, but **no row exists in the
> DB for it** until you create it. Until then `POST /v1/charges` fails with
> `not found`. A redeploy onto a fresh/wiped DB **re-introduces** the mismatch —
> this is not one-time bootstrap, it must be re-checked after any DB reset.

Create the tenant and align the id, on the VPS as `payment` (admin token from
`.env.stg`):

```bash
# 1. create the tenant — capture the generated 32-hex id
TID=$(curl -s -X POST http://127.0.0.1:8080/admin/tenants \
  -H "Authorization: Bearer $PAYMENT_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"sindireceita-stg"}' | sed -n 's/.*"id":"\([0-9a-f]*\)".*/\1/p')
echo "tenantID=$TID"

# 2. set the per-endpoint price (billing ledger), e.g. /v1/notify
curl -s -X POST "http://127.0.0.1:8080/admin/tenants/$TID/pricing" \
  -H "Authorization: Bearer $PAYMENT_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"endpoint":"/v1/notify","price_cents":5}'
```

Then make **every** `tenantId` placeholder in `/opt/payment/.env.stg` equal the
`$TID` just generated — `PAYMENT_WEBHOOK_REFS`, `PAYMENT_TENANT_TOKENS`,
`PAYMENT_BANK_CREDS`, `PAYMENT_BANK_CREDITOR_KEYS` — and
`sudo systemctl restart payment-api`. Verify the tenant resolves before declaring
the deploy good:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8080/v1/charges \
  -H "Authorization: Bearer $PAYMENT_TENANT_TOKEN" -H "Idempotency-Key: stg-probe-1" \
  -H "Content-Type: application/json" \
  -d '{"endpoint":"/v1/notify","amount_cents":500,"currency":"BRL"}'
# → 201 (NOT 404/"not found"). Keep amount_cents ≤ 1000 (≤ R$10) for sandbox auto-confirm.
```

> **Follow-up (tracked separately):** a seed/bootstrap step in `cd-stg.yml` that
> idempotently ensures the tenant row after deploy would remove this manual step.
> Until that lands, this section is the source of truth and **must** be run after
> any fresh-DB deploy. See [SIN-65951](/SIN/issues/SIN-65951).

---

## 10. Rollback (manual, this phase)

Auto-rollback is deferred (ADR-0006). If a deploy goes bad (smoke red, the previous
binary is still running because the new one crash-loops):

1. Re-deploy a known-good commit: in the Actions tab, run `CD staging` via
   `workflow_dispatch` from that commit (or re-run the last green deploy).
2. Or, on the VPS, reinstall a retained good binary and `sudo systemctl restart payment-api`.
3. Confirm with `curl -fsS http://127.0.0.1:8080/healthz` and check the `commit` field.

---

## 11. Troubleshooting: CD fails with `Permission denied (publickey)`

Happened for real after the lmhost cutover (26/08/2026, run `33024654384`). Worth
reading before touching keys, because the obvious suspects were all innocent.

> **The pipeline now catches this by itself.** `cd-stg.yml` runs the read-only
> `preflight` verb between installing the deploy key and shipping the binary, so a
> broken deploy path fails on its own step — named, red, and pointing here — instead
> of surfacing as an opaque `ssh` error at ship time. If you are reading this because
> that step went red, start at item 2: preflight failing already proves items 1 and 3
> are worth checking in that order, and that **nothing was shipped**.

**Diagnose in this order — cheapest and most decisive first.**

1. **Did the runner reach the right host and user?** On the target:

   ```bash
   sudo journalctl -u ssh --since '-1h' | grep payment
   ```

   A line like `Connection closed by authenticating user payment <IP> [preauth]`
   timestamped at the failure proves host, port and **user** are all correct — the
   runner arrived and only the key was refused. `<IP>` is an Azure address (the
   GitHub runner). No such line means the connection never landed: suspect
   `PAYMENT_STG_HOST`, NAT/port-forwarding or the firewall instead.

2. **Is the key in the path `sshd` actually reads?** This is the one that bit us:

   ```bash
   sudo sshd -T | grep -i '^authorizedkeysfile'      # .ssh/authorized_keys — RELATIVE TO HOME
   HOME_DIR="$(getent passwd payment | cut -d: -f6)"
   sudo ssh-keygen -lf "$HOME_DIR/.ssh/authorized_keys"
   ```

   The cutover installed the key at `/home/payment/.ssh/authorized_keys` by following
   §5b when that path was hardcoded, but on `pre-prod` the account's home is
   `/opt/payment`. `sshd` looked in `/opt/payment/.ssh/`, which did not exist, so the
   key was never consulted. Fix: recreate it under the real home
   (`install -d -o payment -g payment -m 0700 "$HOME_DIR/.ssh"`, file 0600).

   **The failure mode is silent by design.** With no `authorized_keys` at all there is
   no `Failed publickey … SHA256:…` line to grep — `sshd` has nothing to reject, so the
   client just exhausts its identities and closes. Absence of that line is itself the
   signal.

3. **Does the key authenticate?** The wrapper exposes a read-only verb, so this is
   safe to run against a live host — it installs nothing and restarts nothing:

   ```bash
   ssh -i payment-cd payment@"$STG_HOST" preflight     # → "[payment-deploy] preflight ok"
   ```

4. **Only then suspect the key material itself.** Compare the fingerprint authorized on
   the host with the one in the secret. Do **not** start by rotating: an unnecessary
   rotation adds a credential to explain later, and if the real cause is the path, the
   new key is refused exactly like the old one — which is, in fact, the test that
   pointed at the path.

**Blast radius while it is broken.** `main` keeps merging and CI keeps passing; only
the deploy fails, so `/healthz` silently keeps serving the last successfully shipped
commit. Ours sat six days behind, and it only surfaced because a merge finally ran the
CD. Check the deployed commit whenever a merge matters:

```bash
curl -fsS https://payment.lmhost.com.br/healthz    # compare `commit` with main HEAD
```
