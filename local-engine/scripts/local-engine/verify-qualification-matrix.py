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
from pathlib import Path, PurePosixPath

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
BACKEND_PROFILE_SCHEMA_VERSION = "Phase1BackendProfileV1"
BACKEND_PROFILE_REF = PurePosixPath("docs/profiles/local-engine/PHASE1_BACKEND_PROFILE.json")
EVIDENCE_DIRECTORY = PurePosixPath("docs/golden/local-engine/evidence")

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
    backend_profiles = _load_backend_profiles(repo_root)
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            _reject("entry must be an object")
        _check_entry(entry, seen, repo_root, backend_profiles, revision)
    return len(entries)


def _load_backend_profiles(repo_root: Path) -> set[str]:
    profile_path = repo_root / Path(*BACKEND_PROFILE_REF.parts)
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        _reject(f"backend profile is unreadable: {exc}")
    if profile.get("schema_version") != BACKEND_PROFILE_SCHEMA_VERSION:
        _reject("unsupported backend profile schema_version")
    profile_ids = profile.get("profile_ids")
    if (
        not isinstance(profile_ids, list)
        or not profile_ids
        or any(not isinstance(profile_id, str) or not profile_id for profile_id in profile_ids)
    ):
        _reject("backend profile must declare non-empty profile_ids")
    return set(profile_ids)


def _resolve_evidence_ref(entry_id: str, evidence_ref: str, repo_root: Path) -> Path:
    if "/" in entry_id or "\\" in entry_id or entry_id in {".", ".."}:
        _reject(f"invalid entry_id for evidence binding: {entry_id!r}")
    if "\\" in evidence_ref:
        _reject(f"{entry_id}: evidence_ref must use a repo-relative POSIX path")
    evidence_path = PurePosixPath(evidence_ref)
    expected = EVIDENCE_DIRECTORY / f"{entry_id}.md"
    if evidence_path.is_absolute() or ".." in evidence_path.parts or evidence_path != expected:
        _reject(f"{entry_id}: evidence_ref is not its canonical qualification evidence path")
    root = repo_root.resolve()
    candidate = repo_root / Path(*evidence_path.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        _reject(f"{entry_id}: evidence_ref does not resolve: {evidence_ref}: {exc}")
    try:
        resolved.relative_to(root)
    except ValueError:
        _reject(f"{entry_id}: evidence_ref escapes repo root: {evidence_ref}")
    if not resolved.is_file():
        _reject(f"{entry_id}: evidence_ref does not resolve to a file: {evidence_ref}")
    return resolved


def _check_evidence_binding(entry: dict, evidence: Path, matrix_revision: str) -> None:
    entry_id = entry["entry_id"]
    try:
        content = evidence.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        _reject(f"{entry_id}: evidence is unreadable: {exc}")
    if not re.search(rf"^# Evidence — {re.escape(entry_id)}[ \t]*$", content, re.MULTILINE):
        _reject(f"{entry_id}: evidence does not bind its entry_id")
    _check_literal_field(content, entry_id, "matrix_revision", matrix_revision)
    _check_literal_field(content, entry_id, "artifact_digest", entry["artifact_digest"])
    _check_byte_length(content, entry)
    _check_literal_field(
        content,
        entry_id,
        "quantization_class",
        entry["quantization_class"],
        aliases=("quantization",),
        casefold=True,
    )
    _check_interpretation_revisions(content, entry)
    _check_literal_field(content, entry_id, "backend_profile", entry["backend_profile"])
    _check_literal_field(content, entry_id, "hardware_class", entry["hardware_class"])
    _check_capabilities(content, entry)


def _field_values(content: str, field: str, aliases: tuple[str, ...] = ()) -> list[str]:
    names = "|".join(re.escape(name) for name in (field, *aliases))
    return re.findall(
        rf"^\|[ \t]*(?:{names})[ \t]*\|[ \t]*([^|\r\n]*)\|[ \t]*$",
        content,
        re.MULTILINE,
    )


def _unquote(value: str) -> str:
    value = value.strip()
    if value.startswith("`") and value.endswith("`") and value.count("`") == 2:
        return value[1:-1]
    return value


def _check_literal_field(
    content: str,
    entry_id: str,
    field: str,
    expected: str,
    *,
    aliases: tuple[str, ...] = (),
    casefold: bool = False,
) -> None:
    values = _field_values(content, field, aliases)
    actual = [_unquote(value) for value in values]
    if casefold:
        actual = [value.casefold() for value in actual]
        expected = expected.casefold()
    if actual != [expected]:
        _reject(f"{entry_id}: evidence does not bind {field}")


def _check_byte_length(content: str, entry: dict) -> None:
    values = _field_values(content, "byte_length")
    normalized = [value.replace(" ", "").replace("\u00a0", "") for value in values]
    if normalized != [str(entry["byte_length"])] or not normalized[0].isdigit():
        _reject(f"{entry['entry_id']}: evidence does not bind byte_length")


def _check_interpretation_revisions(content: str, entry: dict) -> None:
    values = _field_values(content, "interpretation_revisions")
    if len(values) != 1:
        _reject(f"{entry['entry_id']}: evidence does not bind interpretation_revisions")
    revisions = {}
    for part in values[0].split(","):
        match = re.fullmatch(r"[ \t]*([^`\s,]+)[ \t]+`([^`]+)`[ \t]*", part)
        if not match or match.group(1) in revisions:
            _reject(f"{entry['entry_id']}: evidence does not bind interpretation_revisions")
        revisions[match.group(1)] = match.group(2)
    if revisions != entry["interpretation_revisions"]:
        _reject(f"{entry['entry_id']}: evidence does not bind interpretation_revisions")


def _check_capabilities(content: str, entry: dict) -> None:
    values = _field_values(content, "capabilities")
    if len(values) != 1:
        _reject(f"{entry['entry_id']}: evidence does not bind capabilities")
    parts = [part.strip() for part in values[0].split(",")]
    capabilities = [part[1:-1] for part in parts]
    if (
        any(not part.startswith("`") or not part.endswith("`") for part in parts)
        or capabilities != entry["capabilities"]
    ):
        _reject(f"{entry['entry_id']}: evidence does not bind capabilities")


def _check_entry(
    entry: dict,
    seen_ids: set,
    repo_root: Path,
    backend_profiles: set[str],
    matrix_revision: str,
) -> None:
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
    if entry["backend_profile"] not in backend_profiles:
        _reject(f"{entry_id}: backend_profile is absent from the backend profile contract")
    length = entry.get("byte_length")
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        _reject(f"{entry_id}: byte_length must be a positive integer")
    if not isinstance(entry.get("capabilities"), list) or not entry["capabilities"]:
        _reject(f"{entry_id}: capabilities must be a non-empty list")
    interp = entry.get("interpretation_revisions")
    if (
        not isinstance(interp, dict)
        or not interp
        or any(not isinstance(key, str) or not key or not isinstance(value, str) or not value for key, value in interp.items())
    ):
        _reject(f"{entry_id}: interpretation_revisions must be a non-empty object")
    evidence = _resolve_evidence_ref(entry_id, entry["evidence_ref"], repo_root)
    _check_evidence_binding(entry, evidence, matrix_revision)


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
