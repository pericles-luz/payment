# Payment receptor — staging deploy runbook (one-time VPS bootstrap)

> **Audience:** the CEO/operator, run **once** on the VPS. After this, every deploy
> is automated by `.github/workflows/cd-stg.yml` (build → ship → restart → smoke).
> No agent ever runs a command on the VPS. See ADR
> [`docs/security/adr-0006-payment-staging-deploy.md`](../security/adr-0006-payment-staging-deploy.md).

- **Service:** payment receptor, single Go binary `cmd/api`.
- **Listens:** `:8080`, `/healthz`, behind HAProxy at `payment.lmhost.com.br`.
- **VPS:** `143.198.66.140`.
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
```

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

Append to `/home/payment/.ssh/authorized_keys` (create dir as `payment`, mode 0700;
file mode 0600). The `command=` forces every connection through the wrapper:

```bash
sudo install -d -o payment -g payment -m 0700 /home/payment/.ssh
PUB="$(cat payment-cd.pub)"   # the public key you just generated
printf 'command="/opt/payment/bin/payment-deploy.sh",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding %s\n' \
  "$PUB" | sudo -u payment tee -a /home/payment/.ssh/authorized_keys
sudo -u payment chmod 0600 /home/payment/.ssh/authorized_keys
```

> The `scp` upload step in the workflow lands the binary at
> `/opt/payment/incoming/payment-api`; the forced command then validates and
> installs it. (OpenSSH's internal scp transfer is permitted under the forced
> command; interactive exec lands in the wrapper, which rejects everything but
> `deploy`/`preflight`.)

### 5c. The PRIVATE key becomes the `PAYMENT_STG_SSH_KEY` GitHub secret

Keep `payment-cd` (private) **off the VPS and out of any thread**. It goes into
GitHub Actions secrets in step 7. Delete your local copies once the secrets are set.

---

## 6. Capture the VPS host key (no TOFU)

The workflow pins `known_hosts`, so capture it now:

```bash
ssh-keyscan -t ed25519 143.198.66.140
# → 143.198.66.140 ssh-ed25519 AAAA...   (one line)
```

That exact line is the `PAYMENT_STG_HOST_KEY` secret.

---

## 7. Set the GitHub Actions secrets (UPSTREAM repo `pericles-luz/payment`)

The CD job is owner-gated to `pericles-luz`, so the secrets live on the **upstream**
repo (the fork has none and the job is a no-op there). Names used by `cd-stg.yml`:

| Secret | Value |
|--------|-------|
| `PAYMENT_STG_SSH_KEY` | the **private** `payment-cd` key (full PEM, including header/footer) |
| `PAYMENT_STG_HOST` | `143.198.66.140` |
| `PAYMENT_STG_USER` | `payment` |
| `PAYMENT_STG_HOST_KEY` | the `ssh-keyscan` line from step 6 (no TOFU) |
| `PAYMENT_STG_SMOKE_URL` | `https://payment.lmhost.com.br` (the workflow appends `/healthz`) |

```bash
# example with gh CLI (run where the private key file lives):
gh secret set PAYMENT_STG_SSH_KEY   --repo pericles-luz/payment < payment-cd
gh secret set PAYMENT_STG_HOST      --repo pericles-luz/payment --body '143.198.66.140'
gh secret set PAYMENT_STG_USER      --repo pericles-luz/payment --body 'payment'
gh secret set PAYMENT_STG_HOST_KEY  --repo pericles-luz/payment --body '143.198.66.140 ssh-ed25519 AAAA...'
gh secret set PAYMENT_STG_SMOKE_URL --repo pericles-luz/payment --body 'https://payment.lmhost.com.br'
```

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
PAYMENT_C6_SCOPE=REPLACE-scope

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

From here, pushes to upstream `main` that pass `CI` auto-deploy via `cd-stg.yml`,
or trigger a manual deploy from the Actions tab (`workflow_dispatch`).

---

## 10. Rollback (manual, this phase)

Auto-rollback is deferred (ADR-0006). If a deploy goes bad (smoke red, the previous
binary is still running because the new one crash-loops):

1. Re-deploy a known-good commit: in the Actions tab, run `CD staging` via
   `workflow_dispatch` from that commit (or re-run the last green deploy).
2. Or, on the VPS, reinstall a retained good binary and `sudo systemctl restart payment-api`.
3. Confirm with `curl -fsS http://127.0.0.1:8080/healthz` and check the `commit` field.
