#!/usr/bin/env bash
# payment-deploy_test.sh — hermetic guardrail for the VPS deploy wrapper.
#
# The wrapper (payment-deploy.sh) is the ONLY command reachable over the CD deploy
# key AND, since SIN-65902, the sole transport: the CD job streams the binary into
# the `deploy` verb on stdin (there is no scp — a forced command= intercepts every
# connection on the key, with no scp/SFTP exemption). This test pins that contract:
#
#   1. `deploy` reads an ELF binary from stdin → atomic install + scoped restart.
#   2. empty stdin is rejected (no half-deploy).
#   3. non-ELF stdin is rejected (won't crash-loop the unit).
#   4. a smuggled trailer (`deploy; rm -rf /`) keeps only the `deploy` token.
#   5. the allow-list refuses every other verb, INCLUDING a literal
#      `scp -t /opt/payment/incoming/payment-api` — the exact shape OpenSSH would
#      hand the wrapper if the CD job (wrongly) used scp under command=.
#   6. `preflight` is read-only and installs nothing.
#
# It runs without root by rewriting the wrapper's fixed /opt/payment + systemctl
# paths into a sandbox and shimming `sudo`/`systemctl` on PATH. The control flow
# (verb parse, stdin read, ELF check, atomic mv, restart call, cleanup) is the
# real script's. SIN-65902.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRAPPER="${HERE}/payment-deploy.sh"
SANDBOX="$(mktemp -d)"
trap 'rm -rf "${SANDBOX}"' EXIT

mkdir -p "${SANDBOX}/opt/incoming" "${SANDBOX}/opt/bin" "${SANDBOX}/shim"
RESTART_LOG="${SANDBOX}/restart.log"
: >"${RESTART_LOG}"

# Shim systemctl: record invocations instead of touching the host.
cat >"${SANDBOX}/shim/systemctl" <<EOF
#!/usr/bin/env bash
echo "systemctl \$*" >>"${RESTART_LOG}"
exit 0
EOF
# Shim sudo: drop the leading -n and exec the rest (so the scoped restart runs the
# shimmed systemctl). Mirrors \`sudo -n /usr/bin/systemctl restart payment-api\`.
cat >"${SANDBOX}/shim/sudo" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = "-n" ] && shift
exec "$@"
EOF
chmod +x "${SANDBOX}/shim/systemctl" "${SANDBOX}/shim/sudo"

# A copy of the wrapper with the fixed paths rewritten into the sandbox. We do NOT
# edit the real script; we only relocate its three hard-coded constants.
SUT="${SANDBOX}/payment-deploy.sandbox.sh"
sed \
  -e "s#/opt/payment/incoming/payment-api#${SANDBOX}/opt/incoming/payment-api#g" \
  -e "s#/opt/payment/bin#${SANDBOX}/opt/bin#g" \
  -e "s#/usr/bin/systemctl#${SANDBOX}/shim/systemctl#g" \
  "${WRAPPER}" >"${SUT}"
chmod +x "${SUT}"

INCOMING="${SANDBOX}/opt/incoming/payment-api"
INSTALLED="${SANDBOX}/opt/bin/payment-api"
ELF_FIXTURE="${SANDBOX}/fixture.elf"
# Minimal ELF: the 4-byte magic the wrapper greps for, plus a little body so it is
# non-empty. (The wrapper only checks the magic + non-empty, never executes it.)
printf '\x7fELF\x02\x01\x01\x00payload' >"${ELF_FIXTURE}"

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  ok   — %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL — %s\n' "$1"; }

# Run the SUT with a given SSH_ORIGINAL_COMMAND and stdin; capture exit code.
# Usage: run <ssh_original_command> <stdin_file_or_empty>
run() {
  local cmd="$1" stdin="${2:-/dev/null}"
  set +e
  PATH="${SANDBOX}/shim:${PATH}" SSH_ORIGINAL_COMMAND="${cmd}" \
    bash "${SUT}" <"${stdin}" >"${SANDBOX}/out.log" 2>&1
  local rc=$?
  set -e
  return "${rc}"
}

reset_state() {
  rm -f "${INCOMING}" "${INSTALLED}"
  : >"${RESTART_LOG}"
}

echo "payment-deploy.sh guardrail (SIN-65902)"

# 1. Happy path: ELF on stdin → installs + restarts, incoming cleaned up.
reset_state
if run "deploy" "${ELF_FIXTURE}"; then
  if [ -f "${INSTALLED}" ] \
     && cmp -s "${INSTALLED}" "${ELF_FIXTURE}" \
     && grep -q "restart payment-api" "${RESTART_LOG}" \
     && [ ! -f "${INCOMING}" ]; then
    ok "deploy reads stdin → installs binary, restarts unit, cleans up incoming"
  else
    bad "deploy happy path: install/restart/cleanup state wrong"
  fi
else
  bad "deploy with valid ELF on stdin exited non-zero ($(cat "${SANDBOX}/out.log"))"
fi

# 2. Empty stdin → refused, nothing installed.
reset_state
if run "deploy" "/dev/null"; then
  bad "deploy with empty stdin should fail"
else
  if grep -q "empty upload on stdin" "${SANDBOX}/out.log" && [ ! -f "${INSTALLED}" ]; then
    ok "deploy rejects empty stdin (no install)"
  else
    bad "deploy empty stdin: wrong error or binary installed"
  fi
fi

# 3. Non-ELF stdin → refused, nothing installed.
reset_state
printf 'this is not an elf binary' >"${SANDBOX}/junk"
if run "deploy" "${SANDBOX}/junk"; then
  bad "deploy with non-ELF stdin should fail"
else
  if grep -q "not an ELF binary" "${SANDBOX}/out.log" && [ ! -f "${INSTALLED}" ]; then
    ok "deploy rejects non-ELF upload (no install)"
  else
    bad "deploy non-ELF: wrong error or binary installed"
  fi
fi

# 4a. Trailing arguments after the verb are discarded; `deploy --whatever` still
#     deploys (the wrapper reads only the first whitespace-delimited token).
reset_state
if run "deploy --whatever extra" "${ELF_FIXTURE}"; then
  if [ -f "${INSTALLED}" ]; then
    ok "deploy ignores trailing arguments after the verb"
  else
    bad "deploy with trailing args: binary not installed"
  fi
else
  bad "deploy with trailing args exited non-zero ($(cat "${SANDBOX}/out.log"))"
fi

# 4b. A glued metacharacter (no space) makes the whole token != `deploy`, so the
#     allow-list refuses it outright — `deploy;rm -rf /` never installs nor runs rm.
reset_state
if run "deploy;rm -rf /" "${ELF_FIXTURE}"; then
  bad "deploy with glued '; rm' should be refused"
else
  if grep -q "refused" "${SANDBOX}/out.log" && [ ! -f "${INSTALLED}" ]; then
    ok "glued metacharacter ('deploy;rm …') is refused, nothing installed"
  else
    bad "glued metacharacter: not refused cleanly"
  fi
fi

# 5. Allow-list refuses every non-deploy/preflight verb, including a literal scp —
#    the exact SSH_ORIGINAL_COMMAND OpenSSH would deliver if the CD job used scp.
for verb in \
  "scp -t ${SANDBOX}/opt/incoming/payment-api" \
  "rm -rf /" \
  "bash" \
  "" ; do
  reset_state
  label="${verb:-<empty>}"
  if run "${verb}" "${ELF_FIXTURE}"; then
    bad "allow-list should refuse: '${label}'"
  else
    if grep -q "refused" "${SANDBOX}/out.log" && [ ! -f "${INSTALLED}" ]; then
      ok "allow-list refuses '${label}'"
    else
      bad "verb '${label}': not refused cleanly"
    fi
  fi
done

# 6. preflight is read-only: exits 0, installs nothing, no restart.
reset_state
if run "preflight" "/dev/null"; then
  # preflight may query `systemctl status` (logged by the shim) but must never
  # install a binary nor issue a restart.
  if [ ! -f "${INSTALLED}" ] && ! grep -q "restart" "${RESTART_LOG}"; then
    ok "preflight is read-only (no install, no restart)"
  else
    bad "preflight mutated state"
  fi
else
  bad "preflight exited non-zero ($(cat "${SANDBOX}/out.log"))"
fi

echo "---"
echo "passed: ${PASS}  failed: ${FAIL}"
[ "${FAIL}" -eq 0 ] || exit 1
