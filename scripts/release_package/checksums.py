#!/usr/bin/env python3
"""Write sorted checksums for all staged candidate inputs."""

import hashlib
import pathlib
import sys

candidate_directory = pathlib.Path(sys.argv[1])
entries = []
for path in candidate_directory.rglob("*"):
    if not path.is_file() or path.name in {"checksums.sha256", "release-manifest.v1.json"}:
        continue
    relative = path.relative_to(candidate_directory).as_posix()
    entries.append((relative.encode("utf-8"), hashlib.sha256(path.read_bytes()).hexdigest(), relative))
entries.sort(key=lambda entry: entry[0])
(candidate_directory / "checksums.sha256").write_text(
    "".join(f"{digest}  {relative}\n" for _, digest, relative in entries),
    encoding="utf-8",
)
