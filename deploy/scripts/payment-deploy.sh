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
#   deploy     — read the binary from stdin, atomically install it, restart the service.
#   preflight  — read-only sanity check (paths/units present); installs nothing.
#
# Least privilege: this script runs as the non-root `payment` user. The single
# privileged action — restarting the unit — is granted by ONE NOPASSWD sudoers
# line scoped to exactly that command (see docs/deploy/staging.md):
#   payment ALL=(root) NOPASSWD: /usr/bin/systemctl restart payment-api
#
# SIN-65900 (initial wrapper); SIN-65902 (stdin transport — drop scp).

set -euo pipefail

# Fixed, non-overridable paths. Nothing here is taken from the caller.
readonly INCOMING="/opt/payment/incoming/payment-api"   # stdin upload scratch path
readonly BIN_DIR="/opt/payment/bin"
readonly INSTALLED="${BIN_DIR}/payment-api"
readonly UNIT="payment-api"
readonly SYSTEMCTL="/usr/bin/systemctl"

log()  { printf '[payment-deploy] %s\n' "$*" >&2; }
die()  { printf '[payment-deploy] ERROR: %s\n' "$*" >&2; exit 1; }

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
    install -d -m 0755 "$(dirname "${INCOMING}")"
    cat > "${INCOMING}"
    [ -s "${INCOMING}" ] || die "empty upload on stdin"
    # It must be an executable ELF; reject anything that isn't a Linux binary so a
    # bad upload can't be installed and crash-loop the service.
    head -c 4 "${INCOMING}" | grep -q $'\x7fELF' || die "uploaded file is not an ELF binary"

    install -d -m 0755 "${BIN_DIR}"
    chmod 0755 "${INCOMING}"
    # Atomic install: write to a temp name on the SAME filesystem, then rename over
    # the live path. rename(2) is atomic, so a concurrent exec never sees a partial
    # file. The previous binary's open inode keeps running until systemd restarts.
    tmp="${INSTALLED}.new.$$"
    cp -f "${INCOMING}" "${tmp}"
    chmod 0755 "${tmp}"
    mv -f "${tmp}" "${INSTALLED}"
    log "installed new binary at ${INSTALLED}"

    log "restarting ${UNIT} via scoped sudo"
    sudo -n "${SYSTEMCTL}" restart "${UNIT}" || die "systemctl restart ${UNIT} failed"

    # Clean up the upload so a stale binary can't be reinstalled by a later bad
    # invocation.
    rm -f "${INCOMING}"
    log "deploy complete"
    ;;

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
    die "refused: only 'deploy' (and 'preflight') are permitted, got '${verb:-<empty>}'"
    ;;
esac
