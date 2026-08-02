#!/usr/bin/env python3
"""Validate profile metadata and serialize the package input list."""

import json
import pathlib
import sys

profiles = []
for raw_path in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    source = pathlib.Path(raw_path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"ERROR: invalid profile JSON: {source}: {error}") from error
    if not isinstance(payload, dict):
        raise SystemExit(f"ERROR: profile JSON must be an object: {source}")
    name = payload.get("profile_id")
    if not isinstance(name, str) or not name:
        raise SystemExit(f"ERROR: profile_id is required: {source}")
    revision = payload.get("profile_revision")
    if not isinstance(revision, int) or isinstance(revision, bool):
        raise SystemExit(f"ERROR: profile_revision is required: {source}")
    profiles.append({"name": name, "revision": revision, "source_path": raw_path})

pathlib.Path(sys.argv[2]).write_bytes(
    json.dumps(profiles, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    + b"\n"
)
