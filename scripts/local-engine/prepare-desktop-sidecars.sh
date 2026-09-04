#!/usr/bin/env bash
# Local Engine Phase 1 desktop sidecar provisioning + final gates
# (Plan Task 16).
#
# 1. Builds the two Tauri externalBin sidecars (`runned`, `runne`) for
#    the current host triple and installs them under
#    apps/desktop/src-tauri/binaries/ with the platform suffix.
# 2. Runs the Local Engine final verification gates:
#    - backend inventory verifier (99-crate pin profile),
#    - qualification model matrix verifier,
#    - local engine effect crate tests.
#
# Usage: scripts/local-engine/prepare-desktop-sidecars.sh [--skip-tests]

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
STANDALONE_ROOT=${RUNNE_LOCAL_ENGINE_ROOT:-$(cd -- "$REPO_ROOT/../runne-local-engine" && pwd)}
TARGET_TRIPLE=$(rustc -vV | awk '/^host:/ {print $2}')
BINARIES_DIR="$REPO_ROOT/apps/desktop/src-tauri/binaries"

SKIP_TESTS=0
for arg in "$@"; do
  case "$arg" in
    --skip-tests) SKIP_TESTS=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

echo "== building sidecar binaries ($TARGET_TRIPLE)"
cargo build -p runne-daemon --bin runned -p runne-cli --bin runne

mkdir -p "$BINARIES_DIR"
for bin in runned runne; do
  cp "target/debug/$bin" "$BINARIES_DIR/$bin-$TARGET_TRIPLE"
  echo "installed $BINARIES_DIR/$bin-$TARGET_TRIPLE"
done

echo "== local engine final gates"
MATRIX="$STANDALONE_ROOT/docs/profiles/local-engine/PHASE1_QUALIFICATION_MODELS.json"
python3 "$STANDALONE_ROOT/scripts/local-engine/verify_backend_inventory.py" \
  --profile "$STANDALONE_ROOT/docs/profiles/local-engine/PHASE1_BACKEND_PROFILE.json" \
  --lock "$STANDALONE_ROOT/Cargo.lock"
python3 "$STANDALONE_ROOT/scripts/local-engine/verify-qualification-matrix.py" \
  --matrix "$MATRIX" --repo-root "$STANDALONE_ROOT"

if [ "$SKIP_TESTS" -eq 0 ]; then
  (cd "$STANDALONE_ROOT" && cargo test -p runne-daemon-local-engine-effect -p runne-provider-local)
  cargo test -p runne-platform-desktop --test local_model_source
fi

echo "OK: local engine sidecars provisioned and gates passed"
