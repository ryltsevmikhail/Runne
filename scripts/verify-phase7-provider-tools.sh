#!/usr/bin/env bash
set -euo pipefail

fixture="crates/runne-provider-http/tests/fixtures/synthetic_stream.json"
evidence="docs/evidence/PHASE7_PROVIDER_TOOL_EVIDENCE.md"

test -f "$fixture"
test -f "$evidence"
test -f "docs/traceability/phase7-provider-tool-traceability.md"

if grep -R -n -E 'std::process::Command|tokio::process::Command' crates/runne-tools; then
  echo "direct process execution bypass found in runne-tools" >&2
  exit 1
fi

python3 - "$fixture" "$evidence" <<'PY'
import hashlib
import pathlib
import re
import sys

sys.path.insert(0, "scripts")
import pin_lineage

fixture = pathlib.Path(sys.argv[1])
evidence = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
required = [
    f"fixture_sha256: {digest}",
    "phase7a_verdict: COMPLETED",
    "phase7b_plugin_host: COMPLETED",
    "phase7c_mcp_adapter: COMPLETED",
    "production_mcp_sdk_profile: DISABLED_BY_POLICY",
    "live_provider_evaluation: NOT_RUN",
]
missing = [value for value in required if value not in evidence]
if missing:
    raise SystemExit(f"missing Phase 7A evidence fields: {missing}")

source = re.search(r"^source_commit: ([0-9a-f]{40})$", evidence, re.MULTILINE)
reviewed = re.search(r"^reviewed_commit: ([0-9a-f]{40})$", evidence, re.MULTILINE)
integrated = re.search(r"^integrated_commit: ([0-9a-f]{40})$", evidence, re.MULTILINE)
if source is None or reviewed is None or source.group(1) != reviewed.group(1):
    raise SystemExit("Phase 7 exact source/reviewed commit evidence is invalid")
if integrated is None:
    raise SystemExit("Phase 7 integrated commit evidence is missing")
source_binding = pin_lineage.require_lineage(
    evidence, "source_commit", scope=pin_lineage.NON_DOCS
)
reviewed_binding = pin_lineage.require_lineage(
    evidence, "reviewed_commit", scope=pin_lineage.NON_DOCS
)
if source_binding != reviewed_binding:
    raise SystemExit("Phase 7 source/reviewed successor bindings differ")
pin_lineage.require_lineage(evidence, "integrated_commit", scope=pin_lineage.FULL)
PY

cargo test -p runne-provider --all-targets --locked
cargo test -p runne-tools --all-targets --locked
cargo test -p runne-runtime --test provider_tool_loop --locked
cargo test -p runne-provider-http --all-targets --locked
