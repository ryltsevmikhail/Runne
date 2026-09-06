#!/usr/bin/env bash
# Assemble the exact Phase 1 Local Engine candidate (Plan Task 16).
#
# Produces dist/local-engine-candidate/ containing:
#   - runned / runne desktop sidecars (host-triple suffixed),
#   - the llama.cpp worker binary (standalone, feature backend-llama-cpp),
#   - MANIFEST.txt with sha256 of every artifact and the gate evidence.
#
# Signing and notarization are performed on the signing machine
# (mac-product-signing mission) on top of this candidate.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
STANDALONE_ROOT=${RUNNE_LOCAL_ENGINE_ROOT:-$(cd -- "$REPO_ROOT/../runne-local-engine" && pwd)}
TARGET_TRIPLE=$(rustc -vV | awk '/^host:/ {print $2}')
OUT="$REPO_ROOT/dist/local-engine-candidate"

echo "== [1/5] building desktop sidecars"
cargo build -p runne-daemon --bin runned -p runne-cli --bin runne
mkdir -p "$OUT/binaries"
cp "target/debug/runned" "$OUT/binaries/runned-$TARGET_TRIPLE"
cp "target/debug/runne" "$OUT/binaries/runne-$TARGET_TRIPLE"

echo "== [2/5] building the llama.cpp worker (standalone, backend-llama-cpp)"
(cd "$STANDALONE_ROOT" && CARGO_BUILD_JOBS=4 cargo build -p runne-llama-worker --features backend-llama-cpp)
WORKER_BIN="$STANDALONE_ROOT/target/debug/runne-llama-worker"
cp "$WORKER_BIN" "$OUT/binaries/runne-llama-worker-$TARGET_TRIPLE"

echo "== [3/5] running the Local Engine final gates"
python3 "$STANDALONE_ROOT/scripts/local-engine/verify_backend_inventory.py" \
  --profile "$STANDALONE_ROOT/docs/profiles/local-engine/PHASE1_BACKEND_PROFILE.json" \
  --lock "$STANDALONE_ROOT/Cargo.lock"
python3 "$STANDALONE_ROOT/scripts/local-engine/verify-qualification-matrix.py" \
  --matrix "$STANDALONE_ROOT/docs/profiles/local-engine/PHASE1_QUALIFICATION_MODELS.json" \
  --repo-root "$STANDALONE_ROOT"
# Effect boundary tests live in this repo; engine crates in the standalone.
cargo test -p runne-daemon-local-engine-effect
(cd "$STANDALONE_ROOT" && cargo test -p runne-provider-local)
cargo test -p runne-platform-desktop --test local_model_source

echo "== [4/5] hashing artifacts"
: > "$OUT/MANIFEST.txt"
{
  echo "# local-engine Phase 1 candidate"
  echo "# target: $TARGET_TRIPLE"
  echo "# built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$OUT/MANIFEST.txt"
for f in "$OUT"/binaries/*; do
  hash=$(sha256sum "$f" | awk '{print $1}')
  echo "sha256:$hash  $(basename "$f")" >> "$OUT/MANIFEST.txt"
done

echo "== [5/5] verifying the assembled candidate"
python3 "$SCRIPT_DIR/verify-candidate.py" --candidate "$OUT" --target-triple "$TARGET_TRIPLE"

echo "candidate assembled: $OUT"
cat "$OUT/MANIFEST.txt"
