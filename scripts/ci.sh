#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
if [ "$MODE" != "pinned" ] && [ "$MODE" != "msrv" ]; then
    echo "Usage: bash scripts/ci.sh <pinned|msrv>"
    exit 1
fi

RUSTC_VER=$(rustc --version 2>/dev/null | sed 's/rustc //' | cut -d' ' -f1)
if [ -z "$RUSTC_VER" ]; then
    echo "ERROR: rustc not found"
    exit 1
fi

if [ "$MODE" = "pinned" ]; then
    EXPECTED="1.97.1"
else
    EXPECTED="1.95.0"
fi

if [ "$RUSTC_VER" != "$EXPECTED" ]; then
    echo "ERROR: Expected rustc $EXPECTED, got $RUSTC_VER"
    echo "Run: rustup run $EXPECTED bash scripts/ci.sh $MODE"
    exit 1
fi

echo "=== CI: $MODE mode (rustc $RUSTC_VER) ==="

if command -v python3 &>/dev/null; then
    PYTHON_BIN=python3
elif command -v python &>/dev/null; then
    PYTHON_BIN=python
else
    echo "ERROR: python not found"
    exit 1
fi

sha256_file() {
    "$PYTHON_BIN" -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$1"
}

sha256_file_set() {
    "$PYTHON_BIN" -c 'import hashlib, pathlib, sys; h = hashlib.sha256(); [h.update(pathlib.Path(path).read_bytes()) for path in sys.argv[1:]]; print(h.hexdigest())' "$@"
}

# Record lock digest before
LOCK_DIGEST_BEFORE=$(sha256_file Cargo.lock)
PROFILE_FILES=(
    docs/profiles/opencode-baseline-inventory-v1.json
    docs/profiles/opencode-baseline-inventory-v1.digest
    docs/profiles/opencode-baseline-inventory-v2.json
    docs/profiles/opencode-baseline-inventory-v2.digest
    docs/schemas/opencode-baseline-inventory-v1.schema.json
    docs/schemas/opencode-baseline-inventory-v2.schema.json
)
PROFILE_DIGEST_BEFORE=$(sha256_file_set "${PROFILE_FILES[@]}")

if [ "$MODE" = "pinned" ]; then
    echo "--- fmt ---"
    cargo fmt --all --check

    echo "--- source file length ---"
    "$PYTHON_BIN" scripts/check-source-file-length.py --max-lines 300

    echo "--- Task 6C release exclusion ---"
    "$PYTHON_BIN" scripts/verify-task-6c-release-exclusion.py

    "$PYTHON_BIN" -m unittest \
        scripts.tests.test_check_deps \
        scripts.tests.test_check_source_file_length \
        scripts.tests.test_verify_task_6c_release_exclusion \
        -v

    echo "--- check ---"
    cargo check --workspace --all-targets --all-features --locked

    echo "--- clippy ---"
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
else
    echo "--- check ---"
    cargo check --workspace --all-targets --all-features --locked
fi

echo "--- test (unit) ---"
cargo test --workspace --all-targets --all-features --locked

echo "--- test (doc) ---"
cargo test --workspace --doc --all-features --locked

echo "--- doc ---"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked

echo "--- deps ---"
"$PYTHON_BIN" scripts/check-deps.py

echo "--- lock integrity ---"
LOCK_DIGEST_AFTER=$(sha256_file Cargo.lock)
if [ "$LOCK_DIGEST_BEFORE" != "$LOCK_DIGEST_AFTER" ]; then
    echo "ERROR: Cargo.lock changed during CI ($LOCK_DIGEST_BEFORE -> $LOCK_DIGEST_AFTER)"
    exit 1
fi
echo "Cargo.lock unchanged: $LOCK_DIGEST_BEFORE"

echo "--- profile artifact integrity ---"
PROFILE_DIGEST_AFTER=$(sha256_file_set "${PROFILE_FILES[@]}")
if [ "$PROFILE_DIGEST_BEFORE" != "$PROFILE_DIGEST_AFTER" ]; then
    echo "ERROR: profile artifacts changed during CI"
    exit 1
fi
echo "Profile artifacts unchanged: $PROFILE_DIGEST_BEFORE"

echo "=== CI $MODE: PASSED ==="
