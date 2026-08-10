#!/usr/bin/bash
set -euo pipefail

if [[ $# -ne 0 ]]; then
    exit 2
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

readonly pinned_toolchain="1.97.1"
readonly msrv_toolchain="1.95.0"
readonly trusted_bash="${GOCODE_TRUSTED_BASH:?}"
readonly trusted_python="${GOCODE_TRUSTED_PYTHON:?}"
readonly trusted_node="${GOCODE_TRUSTED_NODE:?}"
readonly trusted_pnpm="${GOCODE_TRUSTED_PNPM:?}"
readonly pinned_toolchain_bin="${GOCODE_PINNED_TOOLCHAIN_BIN:?}"
readonly msrv_toolchain_bin="${GOCODE_MSRV_TOOLCHAIN_BIN:?}"

toolchain_bin() {
    local version="$1"
    case "$version" in
        "$pinned_toolchain") printf '%s\n' "$pinned_toolchain_bin" ;;
        "$msrv_toolchain") printf '%s\n' "$msrv_toolchain_bin" ;;
        *) return 2 ;;
    esac
}

run_with_toolchain() {
    local version="$1"
    shift
    local bin_path
    bin_path="$(toolchain_bin "$version")"
    PATH="$bin_path:$PATH" "$@"
}

pnpm_run() {
    "$trusted_node" "$trusted_pnpm" "$@"
}

run_runtime_closure() {
    local version="$1"
    local mode="$2"

    echo "=== Local runtime closure: $mode (Rust $version) ==="
    run_with_toolchain "$version" "$trusted_bash" scripts/verify-phase6-core-closure.sh
    run_with_toolchain "$version" "$trusted_bash" scripts/verify-phase7-closure.sh
    run_with_toolchain "$version" "$trusted_bash" scripts/verify-phase8-opencode.sh
    run_with_toolchain "$version" "$trusted_bash" scripts/verify-canonical-taskrun-daemon.sh
    run_with_toolchain "$version" "$trusted_bash" scripts/verify-secure-replay-desktop.sh runtime
    run_with_toolchain "$version" "$trusted_bash" scripts/ci.sh "$mode"
}

echo "=== Local structural gates ==="
"$trusted_python" scripts/check-source-file-length.py --max-lines 300
"$trusted_python" scripts/verify-task-6c-release-exclusion.py
"$trusted_python" -m unittest \
    scripts.tests.test_check_source_file_length \
    scripts.tests.test_verify_task_6c_release_exclusion \
    -v
"$trusted_python" -m unittest \
    scripts.tests.test_package_release \
    scripts.tests.test_verify_release_integrity \
    scripts.tests.test_verify_release_review \
    -v
"$trusted_python" -m unittest \
    scripts.tests.test_verify_release_review.VerifyReleaseReviewTests.test_fixture_only_structural_candidate_preserves_source_and_candidate_bytes \
    -v
"$trusted_python" -m unittest \
    scripts.tests.test_verify_secure_replay_evidence \
    scripts.tests.test_verify_secure_replay_desktop \
    -v
"$trusted_python" -m unittest scripts.tests.test_verify_test_inventory -v

containment_inventory="$(mktemp "${TMPDIR:-/tmp}/gocode-containment-inventory.XXXXXX")"
process_inventory="$(mktemp "${TMPDIR:-/tmp}/gocode-process-inventory.XXXXXX")"
cleanup() {
    rm -f -- "$containment_inventory" "$process_inventory"
}
trap cleanup EXIT

run_with_toolchain "$pinned_toolchain" \
    cargo test -p gocode-platform --test containment_unavailable -- --list \
    >"$containment_inventory"
"$trusted_python" scripts/verify-test-inventory.py \
    "$containment_inventory" \
    containment_unavailable::absent_certificate_is_unavailable \
    containment_unavailable::certificate_with_wrong_platform_is_unavailable
run_with_toolchain "$pinned_toolchain" \
    cargo test -p gocode-platform --test containment_unavailable -- --nocapture

run_with_toolchain "$pinned_toolchain" \
    cargo test -p gocode-security --test process_containment_admission -- --list \
    >"$process_inventory"
"$trusted_python" scripts/verify-test-inventory.py \
    "$process_inventory" \
    process_containment_admission::missing_certificate_returns_typed_error_without_launching \
    process_containment_admission::mismatched_certificate_never_uses_unrestricted_fallback \
    process_containment_admission::invalid_structured_argv_returns_validation_error_without_launching \
    process_containment_admission::stale_probe_returns_typed_error_without_launching \
    process_containment_admission::matching_caller_constructed_certificate_is_unavailable_without_launching
run_with_toolchain "$pinned_toolchain" \
    cargo test -p gocode-security --test process_containment_admission -- --nocapture

run_runtime_closure "$pinned_toolchain" pinned
run_runtime_closure "$msrv_toolchain" msrv

echo "=== Local frontend closure ==="
pnpm_run install --frozen-lockfile
"$trusted_bash" scripts/verify-secure-replay-desktop.sh frontend
pnpm_run lint
pnpm_run test
pnpm_run typecheck
pnpm_run build
CI=1 pnpm_run test:e2e
pnpm_run validate:docs
pnpm_run lint:architecture
