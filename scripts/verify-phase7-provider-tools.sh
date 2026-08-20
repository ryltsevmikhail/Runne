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
import subprocess
import sys

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
commit = source.group(1)
subprocess.run(["git", "cat-file", "-e", f"{commit}^{{commit}}"], check=True)
subprocess.run(["git", "merge-base", "--is-ancestor", commit, "HEAD"], check=True)
if integrated is None:
    raise SystemExit("Phase 7 integrated commit evidence is missing")
subprocess.run(["git", "cat-file", "-e", f"{integrated.group(1)}^{{commit}}"], check=True)
subprocess.run(["git", "merge-base", "--is-ancestor", integrated.group(1), "HEAD"], check=True)
PY

cargo test -p runne-provider --all-targets --locked
cargo test -p runne-tools --all-targets --locked
cargo test -p runne-runtime --test provider_tool_loop --locked
cargo test -p runne-provider-http --all-targets --locked
