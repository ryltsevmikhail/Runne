#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

input_script="scripts/ci-local-inputs.sh"
state_directory=""
if [[ -n "${GOCODE_CI_INPUT_RECEIPT:-}" ]]; then
    receipt="$GOCODE_CI_INPUT_RECEIPT"
else
    umask 077
    state_directory="$(mktemp -d "${TMPDIR:-/tmp}/gocode-ci-local.XXXXXX")"
    chmod 700 "$state_directory"
    receipt="$state_directory/local-inputs-receipt.json"
fi

cleanup() {
    if [[ -n "$state_directory" ]]; then
        rm -f -- "$receipt"
        rmdir -- "$state_directory"
    fi
}
trap cleanup EXIT

bash "$input_script" "$receipt"
python3 -m scripts.ci_local_receipt validate \
    --receipt "$receipt" \
    --input-script "$input_script" \
    --inventory scripts/rc0_candidate/inventories/source-candidate-v1.json

echo "=== Local CI: PASSED ==="
