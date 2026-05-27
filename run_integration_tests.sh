#!/usr/bin/env bash
# Run every e2e binary in sequence; abort on the first failure.

set -Eeuo pipefail

cd "$(dirname "$0")"

CURRENT_STEP=""
trap 'status=$?; if [[ -n "${CURRENT_STEP}" ]]; then echo >&2; echo "ERROR: step \"${CURRENT_STEP}\" failed with exit code ${status}" >&2; fi' ERR

run_step() {
    local description="$1"
    shift
    CURRENT_STEP="$description"
    echo
    echo "==> ${description}"
    echo "    \$ $*"
    "$@"
}

run_step "withdraw-and-exit" \
    cargo run --release --features prom,e2e --bin withdraw-and-exit
run_step "stake-and-checkpoint" \
    cargo run --release --features prom,e2e --bin stake-and-checkpoint
run_step "stake-and-join-with-outdated-checkpoint" \
    cargo run --release --features prom,e2e --bin stake-and-join-with-outdated-checkpoint
run_step "protocol-params" \
    cargo run --release --features prom,e2e --bin protocol-params
run_step "sync-from-genesis" \
    cargo run --release --features prom,e2e --bin sync-from-genesis
run_step "verify-consensus-state-proof" \
    cargo run --bin verify-consensus-state-proof --features prom,e2e
run_step "observer" \
    cargo run --release --features prom,e2e --bin observer

echo
echo "All e2e binaries completed successfully."
