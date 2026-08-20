#!/usr/bin/env bash
set -euo pipefail

evidence="docs/evidence/PHASE6_SECURITY_PLATFORM_EVIDENCE.md"
roadmap="docs/ROADMAP.md"
status="docs/STATUS.md"

test -f "$evidence"
test -f "$roadmap"
test -f "$status"

python3 - "$evidence" "$roadmap" "$status" <<'PY'
import pathlib
import sys

sys.path.insert(0, "scripts")
import pin_lineage

evidence = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
roadmap = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
status = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")

required_evidence = [
    'status: ready',
    'phase6_core_verdict: COMPLETED',
    'ci_run_id: 30342906041',
    'pinned_ci: PASS',
    'msrv_ci: PASS',
    'phase6b_native_qualification: OPEN',
    '## Phase 6B evidence — OPEN',
]
missing = [value for value in required_evidence if value not in evidence]
if missing:
    raise SystemExit(f"missing Phase 6 Core closure evidence fields: {missing}")

pin_lineage.require_lineage(evidence, "verified_commit", scope=pin_lineage.FULL)

if "## Phase 6 Core — COMPLETE" not in roadmap:
    raise SystemExit("ROADMAP does not mark Phase 6 Core complete")
if "**Phase 6 Core — COMPLETE:**" not in status:
    raise SystemExit("STATUS does not mark Phase 6 Core complete")
if "Phase 6B — OPEN" not in roadmap or "Phase 6B — OPEN" not in status:
    raise SystemExit("Phase 6B native qualification boundary was lost")
PY
