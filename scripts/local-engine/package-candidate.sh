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
ENGINE_ROOT="$REPO_ROOT/local-engine"
TARGET_TRIPLE=$(rustc -vV | awk '/^host:/ {print $2}')
FINAL_OUT="$REPO_ROOT/dist/local-engine-candidate"
OUT_PARENT=$(dirname -- "$FINAL_OUT")
mkdir -p "$OUT_PARENT"
OUT=$(mktemp -d "$OUT_PARENT/.local-engine-candidate.XXXXXX")
BACKUP=""

cleanup() {
  status=$?
  if [[ -n "$OUT" && -e "$OUT" ]]; then
    rm -rf -- "$OUT"
  fi
  if [[ -n "$BACKUP" && -e "$BACKUP" && ! -e "$FINAL_OUT" ]]; then
    mv -- "$BACKUP" "$FINAL_OUT" || true
  fi
  exit "$status"
}
trap cleanup EXIT

target_dir() {
  case "${CARGO_TARGET_DIR:-target}" in
    /*) printf '%s\n' "${CARGO_TARGET_DIR:-target}" ;;
    *) printf '%s/%s\n' "$REPO_ROOT" "${CARGO_TARGET_DIR:-target}" ;;
  esac
}

TARGET_DIR=$(target_dir)

python3 "$SCRIPT_DIR/verify-embedded-source.py"

echo "== [1/5] building desktop sidecars"
(cd "$REPO_ROOT" && cargo build --locked --target-dir "$TARGET_DIR" \
  --target "$TARGET_TRIPLE" -p runne-daemon --bin runned -p runne-cli --bin runne)
mkdir -p "$OUT/binaries"
cp "$TARGET_DIR/$TARGET_TRIPLE/debug/runned" "$OUT/binaries/runned-$TARGET_TRIPLE"
cp "$TARGET_DIR/$TARGET_TRIPLE/debug/runne" "$OUT/binaries/runne-$TARGET_TRIPLE"

echo "== [2/5] building the llama.cpp worker (backend-llama-cpp)"
(cd "$ENGINE_ROOT" && CARGO_BUILD_JOBS=4 cargo build --locked --target-dir "$TARGET_DIR" \
  --target "$TARGET_TRIPLE" -p runne-llama-worker --features backend-llama-cpp)
WORKER_BIN="$TARGET_DIR/$TARGET_TRIPLE/debug/runne-llama-worker"
cp "$WORKER_BIN" "$OUT/binaries/runne-llama-worker-$TARGET_TRIPLE"

echo "== [3/5] running the Local Engine final gates"
python3 "$ENGINE_ROOT/scripts/local-engine/verify_backend_inventory.py" \
  --profile "$ENGINE_ROOT/docs/profiles/local-engine/PHASE1_BACKEND_PROFILE.json" \
  --lock "$ENGINE_ROOT/Cargo.lock"
python3 "$ENGINE_ROOT/scripts/local-engine/verify-qualification-matrix.py" \
  --matrix "$ENGINE_ROOT/docs/profiles/local-engine/PHASE1_QUALIFICATION_MODELS.json" \
  --repo-root "$ENGINE_ROOT"
# Effect boundary tests live in the root workspace; engine crates are nested.
(cd "$REPO_ROOT" && cargo test --locked --target-dir "$TARGET_DIR" \
  -p runne-daemon-local-engine-effect)
(cd "$ENGINE_ROOT" && cargo test --locked --target-dir "$TARGET_DIR" \
  -p runne-provider-local)
(cd "$REPO_ROOT" && cargo test --locked --target-dir "$TARGET_DIR" \
  -p runne-platform-desktop --test local_model_source)

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

if [[ -e "$FINAL_OUT" ]]; then
  BACKUP=$(mktemp -d "$OUT_PARENT/.local-engine-candidate.previous.XXXXXX")
  rmdir "$BACKUP"
  mv -- "$FINAL_OUT" "$BACKUP"
fi
mv -- "$OUT" "$FINAL_OUT"
OUT=""
if [[ -n "$BACKUP" ]]; then
  rm -rf -- "$BACKUP"
  BACKUP=""
fi

echo "candidate assembled: $FINAL_OUT"
cat "$FINAL_OUT/MANIFEST.txt"
