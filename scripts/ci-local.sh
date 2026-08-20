#!/usr/bin/bash
set -euo pipefail
# Root-owned system tools only; macOS keeps a subset (chmod, rm, sh, ...) in /bin.
export PATH="/usr/bin:/bin"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

state_directory=""
if [[ -n "${RUNNE_CI_INPUT_RECEIPT:-}" ]]; then
    receipt="$RUNNE_CI_INPUT_RECEIPT"
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

/usr/bin/python3 -m scripts.ci_local_receipt run --receipt "$receipt"
/usr/bin/python3 -m scripts.ci_local_receipt validate --receipt "$receipt"

echo "=== Local CI: PASSED ==="
