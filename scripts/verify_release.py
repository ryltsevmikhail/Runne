#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import sys

from release_verify.constants import GATE_ORDER
from release_verify.final_gates import finalize
from release_verify.verify import verify_manifest


def main(argv=None):
    values = sys.argv[1:] if argv is None else argv
    if len(values) != 5:
        raise SystemExit("verify_release.py expects five verifier arguments")
    source_root = pathlib.Path(values[0]).resolve()
    source_revision = values[1]
    source_clean = values[2] == "1"
    candidate_root = pathlib.Path(values[3]).resolve()
    fixture_only = values[4] == "1"
    blocked = []

    def block(gate):
        if gate not in blocked:
            blocked.append(gate)

    state = verify_manifest(
        source_root,
        source_revision,
        source_clean,
        candidate_root,
        fixture_only,
        block,
    )
    finalize(block, state, fixture_only)
    blocked.sort(key=GATE_ORDER.index)
    status = "blocked" if blocked else ("fixture-verified" if fixture_only else "verified")
    print(json.dumps({"blocked_gate_ids": blocked, "status": status}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
