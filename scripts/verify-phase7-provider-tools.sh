#!/usr/bin/env bash
set -euo pipefail

fixture="crates/gocode-provider-http/tests/fixtures/synthetic_stream.json"
evidence="docs/evidence/PHASE7_PROVIDER_TOOL_EVIDENCE.md"

test -f "$fixture"
test -f "$evidence"
test -f "docs/traceability/phase7-provider-tool-traceability.md"

if grep -R -n -E 'std::process::Command|tokio::process::Command' crates/gocode-tools; then
  echo "direct process execution bypass found in gocode-tools" >&2
  exit 1
fi

python3 - "$fixture" "$evidence" <<'PY'
import hashlib
import pathlib
import sys

fixture = pathlib.Path(sys.argv[1])
evidence = pathlib.Path(sys.argv[2]).read_text()
digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
required = [
    f"fixture_sha256: {digest}",
    "source_commit: WORKTREE_UNCOMMITTED",
    "phase7a_verdict: IMPLEMENTED_CANDIDATE",
    "phase7b_plugin_host: IMPLEMENTED_CANDIDATE",
    "phase7c_mcp_adapter: IMPLEMENTED_CANDIDATE",
    "production_mcp_sdk_profile: DISABLED_BY_POLICY",
    "live_provider_evaluation: NOT_RUN",
]
missing = [value for value in required if value not in evidence]
if missing:
    raise SystemExit(f"missing Phase 7A evidence fields: {missing}")
PY

cargo test -p gocode-provider --all-targets --locked
cargo test -p gocode-tools --all-targets --locked
cargo test -p gocode-runtime --test provider_tool_loop --locked
cargo test -p gocode-provider-http --all-targets --locked
python3 scripts/validate-docs.py --strict
