#!/usr/bin/env python3
"""Qualification model matrix verifier (Plan Task 22).

Validates that PHASE1_QUALIFICATION_MODELS.json is internally
consistent: every entry carries a digest-shaped artifact reference, a
positive length, non-empty quantization class, backend profile,
hardware class and capabilities, and a non-empty evidence reference
that resolves to a file under the repo root (empty evidence blocks
capability claims). Entry IDs are unique; unknown fields reject.

Usage:
  python3 verify-qualification-matrix.py --matrix MATRIX.json \
      [--repo-root PATH]

Exit 0 = matrix consistent; exit 1 = rejection (reason on stderr).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA_VERSION = "Phase1QualificationModelsV1"

KNOWN_ENTRY_KEYS = {
    "entry_id",
    "artifact_digest",
    "byte_length",
    "quantization_class",
    "interpretation_revisions",
    "backend_profile",
    "hardware_class",
    "capabilities",
    "evidence_ref",
}

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]


class Rejection(Exception):
    pass


def _reject(reason: str) -> None:
    raise Rejection(reason)


def verify_matrix(matrix: dict, repo_root: Path) -> int:
    """Raises Rejection on the first violation; returns entry count."""
    if matrix.get("schema_version") != SCHEMA_VERSION:
        _reject(f"unsupported schema_version: {matrix.get('schema_version')}")
    revision = matrix.get("matrix_revision")
    if not isinstance(revision, str) or not revision:
        _reject("matrix_revision must be a non-empty string")
    entries = matrix.get("entries")
    if not isinstance(entries, list) or not entries:
        _reject("entries must be a non-empty list")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            _reject("entry must be an object")
        _check_entry(entry, seen, repo_root)
    return len(entries)


def _check_entry(entry: dict, seen_ids: set, repo_root: Path) -> None:
    unknown = set(entry.keys()) - KNOWN_ENTRY_KEYS
    if unknown:
        _reject(f"unknown entry fields: {sorted(unknown)}")
    for key in (
        "entry_id",
        "artifact_digest",
        "quantization_class",
        "backend_profile",
        "hardware_class",
        "evidence_ref",
    ):
        value = entry.get(key)
        if not isinstance(value, str) or not value:
            _reject(f"entry field {key!r} must be a non-empty string")
    entry_id = entry["entry_id"]
    if entry_id in seen_ids:
        _reject(f"duplicate entry_id: {entry_id}")
    seen_ids.add(entry_id)
    if not DIGEST_RE.match(entry["artifact_digest"]):
        _reject(f"{entry_id}: artifact_digest is not sha256:<64 hex>")
    length = entry.get("byte_length")
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        _reject(f"{entry_id}: byte_length must be a positive integer")
    if not isinstance(entry.get("capabilities"), list) or not entry["capabilities"]:
        _reject(f"{entry_id}: capabilities must be a non-empty list")
    interp = entry.get("interpretation_revisions")
    if not isinstance(interp, dict) or not interp:
        _reject(f"{entry_id}: interpretation_revisions must be a non-empty object")
    evidence = repo_root / entry["evidence_ref"]
    if not evidence.is_file():
        _reject(f"{entry_id}: evidence_ref does not resolve: {entry['evidence_ref']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--repo-root", default=str(DEFAULT_REPO_ROOT))
    args = parser.parse_args()
    code = main_with_paths(args.matrix, args.repo_root)
    return code


def main_with_paths(matrix_path, repo_root) -> int:
    try:
        matrix = json.loads(Path(matrix_path).read_text(encoding="utf-8"))
        count = verify_matrix(matrix, Path(repo_root).resolve())
    except Rejection as exc:
        print(f"REJECT: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    revision = matrix.get("matrix_revision")
    print(f"OK: qualification matrix consistent ({count} entries, revision {revision})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
