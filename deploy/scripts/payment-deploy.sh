#!/usr/bin/env bash
# payment-deploy.sh — VPS-side deploy wrapper for the payment receptor.
#
# This script is the ONLY command reachable over the CD deploy key. It is pinned
# in the deploy user's ~/.ssh/authorized_keys via:
#
#   command="/opt/payment/bin/payment-deploy.sh",no-pty,no-port-forwarding,\
#   no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA... payment-cd
#
# Because of command=, the verb the CD job asks for arrives in $SSH_ORIGINAL_COMMAND
# (NOT in $@). We validate it against a strict allow-list and refuse everything
# else with a non-zero exit. There is no path to an arbitrary shell over this key,
# and no scp/SFTP surface either: a forced command intercepts EVERY connection on
# the key — there is NO scp exemption under command= (a `scp ...` invocation would
# land here as SSH_ORIGINAL_COMMAND and be refused). So the CD job ships the binary
# by streaming it into THIS wrapper on stdin under the `deploy` verb; the key can
# run only this script. The `deploy` branch reads stdin to the incoming path,
# validates it (non-empty + ELF), then atomically installs + restarts.
#
# Allowed verbs:
#   deploy     — read the service binary from stdin, atomically install it, restart the unit.
#   preflight  — read-only sanity check (paths/units present); installs nothing.
#
#   deploy-c6-webhook-sync, deploy-c6-webhook-probe, deploy-db-migrate,
#   deploy-vault-reseal
#              — read that OPERATOR TOOL from stdin and atomically install it.
#                No restart, no sudo: these are one-shot commands an operator runs,
#                not services.
#
# Why one literal verb per tool, instead of a single `deploy-tool <name>`:
# this wrapper's invariant is that only the FIRST whitespace-delimited token is read and
# NOTHING is taken from the caller (see the fixed paths below). A verb carrying a name
# would mean reading caller input as part of a path, which is precisely the surface the
# forced command exists to eliminate — even with an allow-list on the name. With one
# literal verb per tool the verb is matched against fixed alternatives and the target
# path is a script constant, so no new caller-controlled surface appears at all. The cost
# is one case branch per tool, which is cheap and self-documenting.
#
# Why operator tools ship at all (SIN follow-up to the #54 incident): the CD used to
# build ONLY cmd/api, so every other binary in /opt/payment/bin was hand-installed and
# drifted. c6-webhook-sync sat 25 days stale, missing the boleto channels AND the
# reachability report — and it is the tool an operator consults to decide whether
# production is sane. A tool that silently ages into lying is worse than no tool.
#
# Least privilege: this script runs as the non-root `payment` user. The single
# privileged action — restarting the unit — is granted by ONE NOPASSWD sudoers
# line scoped to exactly that command (see docs/deploy/staging.md):
#   payment ALL=(root) NOPASSWD: /usr/bin/systemctl restart payment-api
#
# SIN-65900 (initial wrapper); SIN-65902 (stdin transport — drop scp).

set -euo pipefail

# Fixed, non-overridable paths. Nothing here is taken from the caller.
readonly INCOMING_DIR="/opt/payment/incoming"           # stdin upload scratch dir
readonly INCOMING="${INCOMING_DIR}/payment-api"         # stdin upload scratch path
readonly BIN_DIR="/opt/payment/bin"
readonly INSTALLED="${BIN_DIR}/payment-api"
readonly UNIT="payment-api"
readonly SYSTEMCTL="/usr/bin/systemctl"

log()  { printf '[payment-deploy] %s\n' "$*" >&2; }
die()  { printf '[payment-deploy] ERROR: %s\n' "$*" >&2; exit 1; }

# receive_binary reads stdin into a staging path and validates it, or dies.
# Shared by the service and the operator-tool branches so the "non-empty + ELF" gate
# can never diverge between them.
receive_binary() {
  local incoming="$1"
  install -d -m 0755 "$(dirname "${incoming}")"
  cat > "${incoming}"
  [ -s "${incoming}" ] || die "empty upload on stdin"
  # It must be an executable ELF; reject anything that isn't a Linux binary so a bad
  # upload can't be installed.
  head -c 4 "${incoming}" | grep -q $'\x7fELF' || die "uploaded file is not an ELF binary"
}

# install_atomic moves a validated staging file over the live path atomically.
# rename(2) is atomic, so a concurrent exec never sees a partial file, and any process
# already running the previous binary keeps its open inode.
install_atomic() {
  local incoming="$1" installed="$2"
  install -d -m 0755 "${BIN_DIR}"
  chmod 0755 "${incoming}"
  local tmp="${installed}.new.$$"
  cp -f "${incoming}" "${tmp}"
  chmod 0755 "${tmp}"
  mv -f "${tmp}" "${installed}"
  rm -f "${incoming}"
}

# install_tool receives and installs ONE operator tool. The name is a literal supplied
# by a case branch below — never caller input — so the paths it builds are as fixed as
# the service ones. No restart and no sudo: an operator tool is a command, not a unit,
# so this path is strictly LESS privileged than `deploy`.
install_tool() {
  local name="$1"
  local incoming="${INCOMING_DIR}/${name}"
  local installed="${BIN_DIR}/${name}"
  log "deploy-${name}: receiving operator tool on stdin → ${incoming}"
  receive_binary "${incoming}"
  install_atomic "${incoming}" "${installed}"
  log "installed operator tool at ${installed} (no restart: not a service)"
}

# Resolve the requested verb. With an authorized_keys command= pin the real verb
# is in SSH_ORIGINAL_COMMAND; fall back to $1 for local/manual invocation by the
# operator. We take ONLY the first whitespace-delimited token and ignore any
# trailing arguments, so `deploy; rm -rf /` cannot smuggle a second command — the
# token is `deploy` and the rest is discarded, then matched against the allow-list.
raw_cmd="${SSH_ORIGINAL_COMMAND:-${1:-}}"
read -r verb _rest <<<"${raw_cmd}" || true

case "${verb}" in
  deploy)
    # The binary arrives on stdin (streamed over the forced-command ssh session);
    # there is no scp. Capture it to the incoming scratch path first, then validate.
    # The incoming dir is provisioned by the bootstrap (see docs/deploy/staging.md).
    log "deploy: receiving binary on stdin → ${INCOMING}"
    receive_binary "${INCOMING}"
    # Atomic install, then restart. install_atomic also removes the staging file so a
    # stale binary can't be reinstalled by a later bad invocation.
    install_atomic "${INCOMING}" "${INSTALLED}"
    log "installed new binary at ${INSTALLED}"

    log "restarting ${UNIT} via scoped sudo"
    sudo -n "${SYSTEMCTL}" restart "${UNIT}" || die "systemctl restart ${UNIT} failed"
    log "deploy complete"
    ;;

  # Operator tools. One literal verb each (see the header): the name passed to
  # install_tool is a constant in THIS script, never caller input.
  deploy-c6-webhook-sync)  install_tool "c6-webhook-sync" ;;
  deploy-c6-webhook-probe) install_tool "c6-webhook-probe" ;;
  deploy-db-migrate)       install_tool "db-migrate" ;;
  deploy-vault-reseal)     install_tool "vault-reseal" ;;

  preflight)
    log "preflight: read-only checks"
    [ -d "${BIN_DIR}" ] || die "missing ${BIN_DIR}"
    [ -x "${SYSTEMCTL}" ] || die "missing ${SYSTEMCTL}"
    "${SYSTEMCTL}" status "${UNIT}" --no-pager >/dev/null 2>&1 \
      && log "unit ${UNIT} is known" \
      || log "unit ${UNIT} not yet active (ok before first deploy)"
    log "preflight ok"
    ;;

  *)
    die "refused: only 'deploy', 'preflight' and the deploy-<tool> verbs are permitted, got '${verb:-<empty>}'"
    ;;
esac
