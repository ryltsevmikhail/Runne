#!/usr/bin/env bash
set -euo pipefail

profile="docs/profiles/opencode-baseline-inventory-v3.json"
profile_digest="docs/profiles/opencode-baseline-inventory-v3.digest"
outcomes="docs/golden/session-v1-route-outcomes-v1.json"

test -f "$profile"
test -f "$profile_digest"
test -f "$outcomes"

python3 - "$profile" "$profile_digest" "$outcomes" <<'PY'
import hashlib
import json
import pathlib
import sys

profile_path = pathlib.Path(sys.argv[1])
sidecar = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip()
actual = hashlib.sha256(profile_path.read_bytes()).hexdigest()
if sidecar not in {actual, f"sha256:{actual}"}:
    raise SystemExit("Phase 8 V3 profile sidecar digest mismatch")

profile = json.loads(profile_path.read_text(encoding="utf-8"))
expected = {
    "session.create",
    "session.prompt",
    "session.prompt_async",
    "session.status",
    "session.abort",
}
verified = {
    entry["inventory_id"]
    for entry in profile["inventory"]
    if entry["status"] == "Verified"
}
if verified != expected:
    raise SystemExit(f"Phase 8 verified inventory mismatch: {verified}")

outcomes = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
if outcomes["baseline_sha"] != profile["baseline_sha"]:
    raise SystemExit("Phase 8 outcome fixture baseline mismatch")
for route in expected - {"session.create"}:
    value = outcomes["routes"].get(route, {})
    if set(value) != {"success", "error", "loss"}:
        raise SystemExit(f"incomplete Phase 8 outcome fixture: {route}")
PY

if grep -R -n -E 'std::env::var|std::env::vars|std::process::Command|tokio::process::Command' \
  crates/runne-opencode-compat crates/runne-http/src/opencode.rs crates/runne-runtime/src/opencode_session.rs; then
  echo "ambient authority found in Phase 8 compatibility path" >&2
  exit 1
fi

cargo test -p runne-opencode-compat --all-targets --locked
cargo test -p runne-runtime --test opencode_session_host --locked
cargo test -p runne-http --test opencode_session_routes --locked
python3 scripts/validate-docs.py --strict
git diff --check
