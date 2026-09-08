#!/usr/bin/env python3
"""Independent verifier for the assembled Local Engine Phase 1 candidate
(Plan Task 16, release_verify part).

Re-checks dist/local-engine-candidate after assembly:
  - MANIFEST.txt exists and parses;
  - every manifest line matches the actual file on disk (sha256);
  - every manifest-listed file exists in the directory and vice versa
    (no unlisted artifacts);
  - the three required binaries are present with the host-triple suffix:
    runned, runne, runne-llama-worker.

Usage:
  python3 verify-candidate.py [--candidate DIR] [--target-triple TRIPLE]

Exit 0 = candidate consistent; exit 1 = rejection (reason on stderr).
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

REQUIRED_BINARIES = ("runned", "runne", "runne-llama-worker")
MANIFEST_LINE = re.compile(r"^sha256:([0-9a-f]{64})  (.+)$")


class Rejection(Exception):
    pass


def verify(candidate: Path, target_triple: str) -> int:
    manifest_path = candidate / "MANIFEST.txt"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise Rejection("MANIFEST.txt missing")

    binaries_dir = candidate / "binaries"
    if binaries_dir.is_symlink() or not binaries_dir.is_dir():
        raise Rejection("binaries/ directory missing")

    recorded: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue  # comments and blank lines carry no hashes
        match = MANIFEST_LINE.match(line)
        if not match:
            raise Rejection(f"malformed MANIFEST line: {line!r}")
        digest, name = match.groups()
        if name in recorded:
            raise Rejection(f"duplicate MANIFEST entry: {name}")
        recorded[name] = digest

    if not recorded:
        raise Rejection("MANIFEST lists no artifacts")

    expected_names = {
        f"{required}-{target_triple}" for required in REQUIRED_BINARIES
    }
    recorded_names = set(recorded)
    if recorded_names != expected_names:
        missing = sorted(expected_names - recorded_names)
        extra = sorted(recorded_names - expected_names)
        details = []
        if missing:
            details.append(f"missing required artifacts: {', '.join(missing)}")
        if extra:
            details.append(f"unexpected artifacts: {', '.join(extra)}")
        raise Rejection("MANIFEST artifact set is not exact: " + "; ".join(details))

    actual = {p.name: p for p in binaries_dir.iterdir()}
    actual_names = set(actual)
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        details = []
        if missing:
            details.append(f"missing binary files: {', '.join(missing)}")
        if extra:
            details.append(f"unexpected entries in binaries/: {', '.join(extra)}")
        raise Rejection("binaries entry set is not exact: " + "; ".join(details))

    for name, expected_digest in recorded.items():
        path = actual[name]
        if path.is_symlink() or not path.is_file():
            raise Rejection(f"manifest artifact is not a regular file: {name}")
        actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_digest != expected_digest:
            raise Rejection(f"sha256 mismatch for {name}: manifest vs disk")

    return len(recorded)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", default=None, help="candidate directory")
    parser.add_argument("--target-triple", default=None)
    args = parser.parse_args()

    candidate = Path(args.candidate) if args.candidate else Path("dist/local-engine-candidate")
    triple = args.target_triple
    if triple is None:
        raw = __import__("subprocess").run(
            ["rustc", "-vV"], capture_output=True, text=True
        ).stdout
        for line in raw.splitlines():
            if line.startswith("host:"):
                triple = line.split(":", 1)[1].strip()
                break
    if triple is None:
        print("ERROR: cannot determine host triple", file=sys.stderr)
        return 1

    try:
        count = verify(candidate, triple)
    except Rejection as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"OK: candidate verified ({count} artifacts, triple {triple})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
