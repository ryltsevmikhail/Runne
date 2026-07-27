#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

EVIDENCE_TEST=crates/gocode-store/tests/evidence_phase3.rs
REQUIRED_TESTS=(
    evidence_fixtures_deterministic
    evidence_shadow_import_e2e_sqlite
    evidence_full_forward_lifecycle_stage_to_retired
    evidence_rollback_recovery_e2e
)

for test_name in "${REQUIRED_TESTS[@]}"; do
    if ! rg -q "^fn ${test_name}\\(\\)" "$EVIDENCE_TEST"; then
        echo "ERROR: missing Phase 3 evidence test: $test_name"
        exit 1
    fi
done

echo "--- Phase 3 SQLite evidence ---"
cargo test -p gocode-store --test evidence_phase3 --locked

echo "--- Migration application contracts ---"
cargo test -p gocode-application --test migration_control --test migration_rollout --locked

echo "--- Migration SQLite and routing contracts ---"
cargo test -p gocode-store --test migration_sqlite --test migration_routing_sqlite --locked
cargo test -p gocode-runtime --test migration_routing --locked

echo "--- Clippy ---"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

echo "--- Documentation ---"
python3 scripts/validate-docs.py --strict

echo "--- Diff integrity ---"
git diff --check

echo "Phase 3 integration evidence: PASSED"
