#!/usr/bin/env python3
"""Write deterministic provenance attestation for a staged candidate."""

import hashlib
import json
import pathlib
import sys

profiles = [
    pathlib.Path(path)
    for path in pathlib.Path(sys.argv[6]).read_text(encoding="utf-8").splitlines()
]
lanes = []
for lane_id, version in (("pinned-1.97.1", "1.97.1"), ("msrv-1.95.0", "1.95.0")):
    lanes.append(
        {
            "cargo_version": version,
            "hosted_execution_slots": [
                {"platform": platform, "status": "planned"}
                for platform in ("linux", "macos", "windows")
            ],
            "lane_id": lane_id,
            "rustc_version": version,
        }
    )
payload = {
    "artifact_sha256": sys.argv[5],
    "candidate_digest": sys.argv[2],
    "profile_digests": [hashlib.sha256(profile.read_bytes()).hexdigest() for profile in profiles],
    "qualification_lanes": lanes,
    "source_revision": sys.argv[3],
    "target": sys.argv[4],
}
pathlib.Path(sys.argv[1]).write_bytes(
    json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
)
