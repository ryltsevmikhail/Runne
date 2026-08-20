#!/usr/bin/env bash
set -euo pipefail

evidence="docs/evidence/PHASE7_PROVIDER_TOOL_EVIDENCE.md"
traceability="docs/traceability/phase7-provider-tool-traceability.md"
phase6_evidence="docs/evidence/PHASE6_SECURITY_PLATFORM_EVIDENCE.md"

test -f "$evidence"
test -f "$traceability"
test -f "$phase6_evidence"

bash scripts/verify-phase6-core-closure.sh

if grep -R -n -E 'std::process::Command|tokio::process::Command|std::env::var|std::env::vars' \
  crates/runne-plugin-host crates/runne-mcp; then
  echo "ambient process or environment authority found in Phase 7B/7C" >&2
  exit 1
fi

if cargo tree -p runne-mcp --edges normal | grep -E '(^|[[:space:]])(rmcp|reqwest|oauth2)[[:space:]]'; then
  echo "unapproved MCP SDK/network/OAuth dependency found" >&2
  exit 1
fi

if grep -R -n -E 'McpSdkIntegrationAuthorityPort|PRODUCTION_MCP_SDK_ENABLED:[[:space:]]*bool[[:space:]]*=[[:space:]]*true' \
  crates/runne-mcp/src crates/runne-runtime/src; then
  echo "production MCP SDK activation must remain structurally disabled" >&2
  exit 1
fi

python3 - "$evidence" "$traceability" "$phase6_evidence" <<'PY'
import pathlib
import re
import sys

sys.path.insert(0, "scripts")
import pin_lineage

evidence = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
traceability = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
phase6 = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")

required_evidence = [
    "phase7_verdict: COMPLETED",
    "phase7b_plugin_host: COMPLETED",
    "phase7c_mcp_adapter: COMPLETED",
    "production_mcp_sdk_profile: DISABLED_BY_POLICY",
    "ci_run_id: 30386327502",
    "pinned_ci: PASS",
    "msrv_ci: PASS",
    "phase6_evidence_ref: docs/evidence/PHASE6_SECURITY_PLATFORM_EVIDENCE.md",
]
missing = [item for item in required_evidence if item not in evidence]
if missing:
    raise SystemExit(f"missing Phase 7 closure evidence fields: {missing}")

source = re.search(r"^source_commit: ([0-9a-f]{40})$", evidence, re.MULTILINE)
reviewed = re.search(r"^reviewed_commit: ([0-9a-f]{40})$", evidence, re.MULTILINE)
integrated = re.search(r"^integrated_commit: ([0-9a-f]{40})$", evidence, re.MULTILINE)
if source is None or reviewed is None or source.group(1) != reviewed.group(1):
    raise SystemExit("Phase 7 exact source/reviewed commit evidence is invalid")
if integrated is None:
    raise SystemExit("Phase 7 integrated commit evidence is missing")
pin_lineage.require_lineage(evidence, "source_commit")
pin_lineage.require_lineage(evidence, "integrated_commit")

for stale in [
    "IMPLEMENTED_CANDIDATE",
    "phase7b_plugin_host: OPEN",
    "phase7c_mcp_adapter: OPEN",
    "pinned_ci: OPEN",
    "msrv_ci: OPEN",
]:
    if stale in evidence:
        raise SystemExit(f"stale Phase 7 closure marker: {stale}")

if (
    "| Plugin package/activation authority |" not in traceability
    or "| MCP bounded transport |" not in traceability
):
    raise SystemExit("Phase 7B/7C traceability rows missing")
if (
    "phase6_core_verdict: COMPLETED" not in phase6
    or "phase6b_native_qualification: OPEN" not in phase6
):
    raise SystemExit("Phase 6 Core/6B evidence boundary is invalid")
PY

bash scripts/verify-phase7-provider-tools.sh
python3 scripts/check-deps.py
cargo test -p runne-plugin-host --all-targets --locked
cargo test -p runne-mcp --all-targets --locked
cargo test -p runne-runtime --test plugin_mcp_supervision --locked
cargo test -p runne-tools --all-targets --locked
git diff --check
