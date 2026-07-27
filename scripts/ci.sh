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

# Record lock digest before
LOCK_DIGEST_BEFORE=$(shasum -a 256 Cargo.lock 2>/dev/null | awk '{print $1}')
PROFILE_FILES=(
    docs/profiles/opencode-baseline-inventory-v1.json
    docs/profiles/opencode-baseline-inventory-v1.digest
    docs/profiles/opencode-baseline-inventory-v2.json
    docs/profiles/opencode-baseline-inventory-v2.digest
    docs/schemas/opencode-baseline-inventory-v1.schema.json
    docs/schemas/opencode-baseline-inventory-v2.schema.json
)
PROFILE_DIGEST_BEFORE=$(
    shasum -a 256 "${PROFILE_FILES[@]}" 2>/dev/null \
        | shasum -a 256 \
        | awk '{print $1}'
)

if [ "$MODE" = "pinned" ]; then
    echo "--- fmt ---"
    cargo fmt --all --check

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
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found in PATH"
    exit 1
fi
python3 scripts/check-deps.py

if [ "$MODE" = "pinned" ]; then
    echo "--- docs ---"
    python3 scripts/validate-docs.py --strict
fi

echo "--- lock integrity ---"
LOCK_DIGEST_AFTER=$(shasum -a 256 Cargo.lock 2>/dev/null | awk '{print $1}')
if [ "$LOCK_DIGEST_BEFORE" != "$LOCK_DIGEST_AFTER" ]; then
    echo "ERROR: Cargo.lock changed during CI ($LOCK_DIGEST_BEFORE -> $LOCK_DIGEST_AFTER)"
    exit 1
fi
echo "Cargo.lock unchanged: $LOCK_DIGEST_BEFORE"

echo "--- profile artifact integrity ---"
PROFILE_DIGEST_AFTER=$(
    shasum -a 256 "${PROFILE_FILES[@]}" 2>/dev/null \
        | shasum -a 256 \
        | awk '{print $1}'
)
if [ "$PROFILE_DIGEST_BEFORE" != "$PROFILE_DIGEST_AFTER" ]; then
    echo "ERROR: profile artifacts changed during CI"
    exit 1
fi
echo "Profile artifacts unchanged: $PROFILE_DIGEST_BEFORE"

echo "=== CI $MODE: PASSED ==="
