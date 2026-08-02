#!/usr/bin/env python3
"""Compute the canonical digest of release candidate metadata."""

import hashlib
import json
import sys

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
candidate = {
    "lockfile_digest": sys.argv[3],
    "qualification_lanes": lanes,
    "release_version": sys.argv[2],
    "source_revision": sys.argv[1],
}
encoded = json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
    "utf-8"
)
print(hashlib.sha256(encoded).hexdigest())
