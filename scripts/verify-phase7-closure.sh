#!/usr/bin/env bash
set -euo pipefail

evidence="docs/evidence/PHASE7_PROVIDER_TOOL_EVIDENCE.md"
traceability="docs/traceability/phase7-provider-tool-traceability.md"
phase6_evidence="docs/evidence/PHASE6_SECURITY_PLATFORM_EVIDENCE.md"

test -f "$evidence"
test -f "$traceability"
test -f "$phase6_evidence"

if grep -R -n -E 'std::process::Command|tokio::process::Command|std::env::var|std::env::vars' \
  crates/gocode-plugin-host crates/gocode-mcp; then
  echo "ambient process or environment authority found in Phase 7B/7C" >&2
  exit 1
fi

if cargo tree -p gocode-mcp --edges normal | grep -E '(^|[[:space:]])(rmcp|reqwest|oauth2)[[:space:]]'; then
  echo "unapproved MCP SDK/network/OAuth dependency found" >&2
  exit 1
fi

if rg -n 'McpSdkIntegrationAuthorityPort|PRODUCTION_MCP_SDK_ENABLED:[[:space:]]*bool[[:space:]]*=[[:space:]]*true' \
  crates/gocode-mcp/src crates/gocode-runtime/src; then
  echo "production MCP SDK activation must remain structurally disabled" >&2
  exit 1
fi

python3 - "$evidence" "$traceability" "$phase6_evidence" <<'PY'
import pathlib
import re
import subprocess
import sys

evidence = pathlib.Path(sys.argv[1]).read_text()
traceability = pathlib.Path(sys.argv[2]).read_text()
phase6 = pathlib.Path(sys.argv[3]).read_text()

required_evidence = [
    "phase7_verdict: IMPLEMENTED_CANDIDATE",
    "phase7b_plugin_host: IMPLEMENTED_CANDIDATE",
    "phase7c_mcp_adapter: IMPLEMENTED_CANDIDATE",
    "production_mcp_sdk_profile: DISABLED_BY_POLICY",
    "pinned_ci: OPEN",
    "msrv_ci: OPEN",
    "phase6_evidence_ref: docs/evidence/PHASE6_SECURITY_PLATFORM_EVIDENCE.md",
]
missing = [item for item in required_evidence if item not in evidence]
if missing:
    raise SystemExit(f"missing Phase 7 closure evidence fields: {missing}")

source = re.search(r"^source_commit: ([0-9a-f]{40})$", evidence, re.MULTILINE)
reviewed = re.search(r"^reviewed_commit: ([0-9a-f]{40})$", evidence, re.MULTILINE)
if source is None or reviewed is None or source.group(1) != reviewed.group(1):
    raise SystemExit("Phase 7 exact source/reviewed commit evidence is invalid")
commit = source.group(1)
subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], check=True)
subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"], check=True)

for stale in ["phase7b_plugin_host: OPEN", "phase7c_mcp_adapter: OPEN"]:
    if stale in evidence:
        raise SystemExit(f"stale Phase 7 closure marker: {stale}")

if (
    "| Plugin package/activation authority |" not in traceability
    or "| MCP bounded transport |" not in traceability
):
    raise SystemExit("Phase 7B/7C traceability rows missing")
if "status: partial" not in phase6:
    raise SystemExit("Phase 6 evidence status changed without an exact replacement artifact")
PY

bash scripts/verify-phase7-provider-tools.sh
python3 scripts/check-deps.py
cargo test -p gocode-plugin-host --all-targets --locked
cargo test -p gocode-mcp --all-targets --locked
cargo test -p gocode-runtime --test plugin_mcp_supervision --locked
cargo test -p gocode-tools --all-targets --locked
python3 scripts/validate-docs.py --strict
git diff --check
