#!/usr/bin/env bash
# coverage.sh — run tests with coverage and fail if total statement coverage is
# at or below the threshold (default 85%). The cmd/ entrypoints are wiring-only
# (no business logic) and are excluded from the coverage denominator; they are
# still compiled by `go build ./...` and `go vet`.
set -euo pipefail

THRESHOLD="${1:-85}"

# Packages under test = everything except the cmd/ entrypoints.
pkgs="$(go list ./... | grep -v '/cmd/')"

go test -count=1 -covermode=atomic -coverprofile=coverage.out ${pkgs}

total="$(go tool cover -func=coverage.out | awk '/^total:/ {sub(/%/, "", $3); print $3}')"
echo "total coverage: ${total}%"

# Fail if total <= threshold (the gate requires strictly greater than 85%).
awk -v t="${total}" -v th="${THRESHOLD}" 'BEGIN { exit !(t+0 > th+0) }' || {
  echo "FAIL: coverage ${total}% is not greater than ${THRESHOLD}%" >&2
  exit 1
}
echo "OK: coverage ${total}% > ${THRESHOLD}%"
