#!/usr/bin/bash
set -euo pipefail

if [[ $# -ne 0 ]]; then
    exit 2
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

readonly pinned_toolchain="1.97.1"
readonly msrv_toolchain="1.95.0"
readonly trusted_bash="${RUNNE_TRUSTED_BASH:?}"
readonly trusted_python="${RUNNE_TRUSTED_PYTHON:?}"
readonly trusted_node="${RUNNE_TRUSTED_NODE:?}"
readonly trusted_pnpm="${RUNNE_TRUSTED_PNPM:?}"
readonly eslint_target="${RUNNE_FRONTEND_ESLINT:?}"
readonly vitest_target="${RUNNE_FRONTEND_VITEST:?}"
readonly vue_tsc_target="${RUNNE_FRONTEND_VUE_TSC:?}"
readonly vite_target="${RUNNE_FRONTEND_VITE:?}"
readonly playwright_target="${RUNNE_FRONTEND_PLAYWRIGHT:?}"
readonly pinned_toolchain_bin="${RUNNE_PINNED_TOOLCHAIN_BIN:?}"
readonly msrv_toolchain_bin="${RUNNE_MSRV_TOOLCHAIN_BIN:?}"

# Canonical receipt gate runs every section below. The scoped runner
# (scripts/ci-local-scoped.sh) selects a subset via RUNNE_SCOPED_CI_GATES
# so path-filtered changes never run unrelated closures.
scoped_gates="${RUNNE_SCOPED_CI_GATES:-}"
gate_enabled() {
    if [[ -z "$scoped_gates" ]]; then
        return 0
    fi
    [[ " $scoped_gates " == *" $1 "* ]]
}

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
    PATH="$bin_path:$PATH" RUSTC="$bin_path/rustc" RUSTDOC="$bin_path/rustdoc" "$@"
}

pnpm_run() {
    "$trusted_node" "$trusted_pnpm" "$@"
}

node_at() {
    local directory="$1"
    local target="$2"
    shift 2
    (cd "$directory" && "$trusted_node" "$target" "$@")
}

typecheck_frontend() {
    node_at apps/desktop "$vue_tsc_target" -b
    node_at apps/site "$vue_tsc_target" -b
    node_at packages/product "$vue_tsc_target" --noEmit -p tsconfig.json
}

test_frontend() {
    node_at apps/desktop "$vitest_target" run
    node_at apps/site "$vitest_target" run
    node_at packages/product "$vitest_target" run
}

validate_frontend_contracts() {
    node_at apps/desktop "$vitest_target" run
    typecheck_frontend
    "$trusted_node" "$playwright_target" test tests/desktop/e2e/replay-resume.spec.ts
    "$trusted_python" scripts/desktop/validate_architecture.py
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

if gate_enabled local-structural; then
    echo "=== Local structural gates ==="
    "$trusted_python" scripts/check-source-file-length.py --max-lines 300
    "$trusted_python" scripts/verify-task-6c-release-exclusion.py
    "$trusted_python" -m unittest \
        scripts.tests.test_check_deps_macos_process_identity \
        scripts.tests.test_check_source_file_length \
        scripts.desktop.tests.test_validate_architecture \
        scripts.tests.test_verify_task_6c_release_exclusion \
        scripts.tests.test_ci_local_receipt_compatibility \
        scripts.tests.test_ci_local_scope \
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
fi

if gate_enabled containment; then
    containment_inventory="$(mktemp "${TMPDIR:-/tmp}/runne-containment-inventory.XXXXXX")"
    process_inventory="$(mktemp "${TMPDIR:-/tmp}/runne-process-inventory.XXXXXX")"
    cleanup() {
        rm -f -- "$containment_inventory" "$process_inventory"
    }
    trap cleanup EXIT

    run_with_toolchain "$pinned_toolchain" \
        cargo test -p runne-platform --test containment_unavailable -- --list \
        >"$containment_inventory"
    "$trusted_python" scripts/verify-test-inventory.py \
        "$containment_inventory" \
        containment_unavailable::absent_certificate_is_unavailable \
        containment_unavailable::certificate_with_wrong_platform_is_unavailable
    run_with_toolchain "$pinned_toolchain" \
        cargo test -p runne-platform --test containment_unavailable -- --nocapture

    run_with_toolchain "$pinned_toolchain" \
        cargo test -p runne-security --test process_containment_admission -- --list \
        >"$process_inventory"
    "$trusted_python" scripts/verify-test-inventory.py \
        "$process_inventory" \
        process_containment_admission::missing_certificate_returns_typed_error_without_launching \
        process_containment_admission::mismatched_certificate_never_uses_unrestricted_fallback \
        process_containment_admission::invalid_structured_argv_returns_validation_error_without_launching \
        process_containment_admission::stale_probe_returns_typed_error_without_launching \
        process_containment_admission::matching_caller_constructed_certificate_is_unavailable_without_launching
    run_with_toolchain "$pinned_toolchain" \
        cargo test -p runne-security --test process_containment_admission -- --nocapture
    run_with_toolchain "$pinned_toolchain" \
        cargo test -p runne-daemon --test protected_bundled_runtime_process \
        --locked --features test-support,desktop-protected
fi

if gate_enabled runtime-pinned; then
    run_runtime_closure "$pinned_toolchain" pinned
fi
if gate_enabled runtime-msrv; then
    run_runtime_closure "$msrv_toolchain" msrv
fi

if gate_enabled frontend; then
    echo "=== Local frontend closure ==="
    pnpm_run install --frozen-lockfile --offline --ignore-scripts \
        --verify-store-integrity --store-dir "$PNPM_STORE_DIR"
    "$trusted_bash" scripts/verify-secure-replay-desktop.sh frontend
    validate_frontend_contracts
    "$trusted_node" "$eslint_target" .
    test_frontend
    typecheck_frontend
    node_at apps/desktop "$vue_tsc_target" -b
    node_at apps/desktop "$vite_target" build
    node_at apps/site "$vue_tsc_target" -b
    node_at apps/site "$repo_root/apps/site/scripts/build.mjs"
    CI=1 "$trusted_node" "$playwright_target" test
    "$trusted_python" -m unittest scripts.desktop.tests.test_desktop_qualification_workflow -v
    "$trusted_python" -m unittest scripts.tests.test_desktop_capability_manifest -v
    "$trusted_python" scripts/desktop/validate_architecture.py
fi
