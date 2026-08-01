#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

pinned_toolchain="${GOCODE_PINNED_TOOLCHAIN:-1.97.1}"
msrv_toolchain="${GOCODE_MSRV_TOOLCHAIN:-1.95.0}"

toolchain_bin() {
    local version="$1"
    local rustc_path
    rustc_path="$(rustup which --toolchain "$version" rustc)"
    printf '%s\n' "${rustc_path%/rustc}"
}

run_with_toolchain() {
    local version="$1"
    shift
    local bin_path
    bin_path="$(toolchain_bin "$version")"
    env PATH="$bin_path:$PATH" "$@"
}

run_runtime_closure() {
    local version="$1"
    local mode="$2"

    echo "=== Local runtime closure: $mode (Rust $version) ==="
    run_with_toolchain "$version" bash scripts/verify-phase6-core-closure.sh
    run_with_toolchain "$version" bash scripts/verify-phase7-closure.sh
    run_with_toolchain "$version" bash scripts/verify-phase8-opencode.sh
    run_with_toolchain "$version" bash scripts/verify-canonical-taskrun-daemon.sh
    run_with_toolchain "$version" bash scripts/verify-secure-replay-desktop.sh runtime
    run_with_toolchain "$version" bash scripts/ci.sh "$mode"
}

if ! command -v rustup >/dev/null 2>&1; then
    echo "ERROR: rustup is required for pinned and MSRV qualification" >&2
    exit 1
fi
if ! command -v pnpm >/dev/null 2>&1; then
    echo "ERROR: pnpm is required for frontend qualification" >&2
    exit 1
fi

echo "=== Local structural gates ==="
python3 scripts/check-source-file-length.py --max-lines 300 --report
python3 -m unittest \
    scripts.tests.test_package_release \
    scripts.tests.test_verify_release_integrity \
    scripts.tests.test_verify_release_review \
    -v
python3 -m unittest \
    scripts.tests.test_verify_release_review.VerifyReleaseReviewTests.test_fixture_only_structural_candidate_preserves_source_and_candidate_bytes \
    -v
python3 -m unittest \
    scripts.tests.test_verify_secure_replay_evidence \
    scripts.tests.test_verify_secure_replay_desktop \
    -v
python3 -m unittest scripts.tests.test_verify_test_inventory -v

containment_inventory="$(mktemp "${TMPDIR:-/tmp}/gocode-containment-inventory.XXXXXX")"
process_inventory="$(mktemp "${TMPDIR:-/tmp}/gocode-process-inventory.XXXXXX")"
cleanup() {
    rm -f -- "$containment_inventory" "$process_inventory"
}
trap cleanup EXIT

run_with_toolchain "$pinned_toolchain" \
    cargo test -p gocode-platform --test containment_unavailable -- --list \
    >"$containment_inventory"
python3 scripts/verify-test-inventory.py \
    "$containment_inventory" \
    containment_unavailable::absent_certificate_is_unavailable \
    containment_unavailable::certificate_with_wrong_platform_is_unavailable
run_with_toolchain "$pinned_toolchain" \
    cargo test -p gocode-platform --test containment_unavailable -- --nocapture

run_with_toolchain "$pinned_toolchain" \
    cargo test -p gocode-security --test process_containment_admission -- --list \
    >"$process_inventory"
python3 scripts/verify-test-inventory.py \
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
pnpm install --frozen-lockfile
bash scripts/verify-secure-replay-desktop.sh frontend
pnpm lint
pnpm test
pnpm typecheck
pnpm build
CI=1 pnpm test:e2e
pnpm validate:docs
pnpm lint:architecture

echo "=== Local CI: PASSED ==="
