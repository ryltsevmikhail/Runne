#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

INVENTORY=scripts/rc0_candidate/inventories/source-candidate-v1.json
SOURCE_SHA=$(git rev-parse HEAD)
TOOLCHAIN=$(rustc -V)
umask 077
EVIDENCE_DIR=$(mktemp -d)
STDERR_FILE=$(mktemp)
trap 'rm -rf "$EVIDENCE_DIR" "$STDERR_FILE"' EXIT

emit_stderr() {
    local identifier=$1 stage=$2
    if [[ -s "$STDERR_FILE" ]]; then
        echo "DIAGNOSTIC: $identifier $stage stderr" >&2
        cat "$STDERR_FILE" >&2
    fi
}

run_tuple() {
    local identifier=$1 package=$2 target=$3 selector=$4 source_sha=$5 expected_toolchain=$6 expected_digest=$7
    local digest_file="$EVIDENCE_DIR/$identifier.digest"
    if [[ "$TOOLCHAIN" != "$expected_toolchain" ]]; then
        echo "ERROR: $identifier toolchain changed" >&2
        return 1
    fi
    set +e
    cargo test --locked -p "$package" --test "$target" -- --list 2>"$STDERR_FILE" |
        python3 scripts/phase3_inventory.py list-digest "$selector" >"$digest_file"
    local statuses=("${PIPESTATUS[@]}")
    set -e
    if (( statuses[0] != 0 )); then
        echo "ERROR: $identifier list Cargo command failed" >&2
        emit_stderr "$identifier" list
        return 1
    fi
    if (( statuses[1] != 0 )); then
        echo "ERROR: $identifier list parser failed" >&2
        emit_stderr "$identifier" list
        return 1
    fi
    emit_stderr "$identifier" list
    if [[ $(<"$digest_file") != "$expected_digest" ]]; then
        echo "ERROR: $identifier inventory digest changed" >&2
        return 1
    fi
    set +e
    cargo test --locked -p "$package" --test "$target" "$selector" -- --exact 2>"$STDERR_FILE" |
        python3 scripts/phase3_inventory.py exact "$selector"
    statuses=("${PIPESTATUS[@]}")
    set -e
    if (( statuses[0] != 0 )); then
        echo "ERROR: $identifier exact Cargo command failed" >&2
        emit_stderr "$identifier" exact
        return 1
    fi
    if (( statuses[1] != 0 )); then
        echo "ERROR: $identifier exact parser failed" >&2
        emit_stderr "$identifier" exact
        return 1
    fi
    emit_stderr "$identifier" exact
    echo "tuple=$identifier package=$package target=$target test=$selector source_sha=$source_sha toolchain=$expected_toolchain inventory_digest=$expected_digest"
}

echo "--- Phase 3 exact integration evidence ---"
tuple_rows=$(python3 scripts/phase3_inventory.py tuples "$INVENTORY" "$SOURCE_SHA")
while IFS=$'\t' read -r identifier package target selector source_sha toolchain digest; do
    [[ -z "$identifier" ]] && continue
    run_tuple "$identifier" "$package" "$target" "$selector" "$source_sha" "$toolchain" "$digest"
done <<< "$tuple_rows"

echo "--- Clippy ---"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

echo "--- Documentation ---"
python3 scripts/validate-docs.py --strict

echo "--- Diff integrity ---"
git diff --check

echo "Phase 3 integration evidence: PASSED"
