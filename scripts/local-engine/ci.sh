#!/usr/bin/env bash
# Contract tests for the in-repository engine workspace. Native inference and
# model/device qualification remain explicit, separate gates.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
ENGINE_ROOT="$REPO_ROOT/local-engine"
python3 "$REPO_ROOT/scripts/local-engine/verify-embedded-source.py"
MODE="${1:-pinned}"
case "$MODE" in
    pinned|msrv) ;;
    *) echo "Usage: bash scripts/local-engine/ci.sh [pinned|msrv]" >&2; exit 2 ;;
esac

cd "$ENGINE_ROOT"
echo "=== Local Engine contracts ($MODE; native backend disabled) ==="
python3 scripts/local-engine/verify_backend_inventory.py \
    --profile docs/profiles/local-engine/PHASE1_BACKEND_PROFILE.json --lock Cargo.lock
python3 scripts/local-engine/verify-qualification-matrix.py \
    --matrix docs/profiles/local-engine/PHASE1_QUALIFICATION_MODELS.json \
    --repo-root "$ENGINE_ROOT"
python3 -m unittest discover -s scripts/tests -v
cargo metadata --no-deps --format-version 1 --locked > /dev/null
if [ "$MODE" = pinned ]; then
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
fi
cargo test --workspace --locked
echo "=== Local Engine contract checks passed; native qualification not run ==="
