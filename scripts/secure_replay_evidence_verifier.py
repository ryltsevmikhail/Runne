"""Git-object and canonical-JSON checks for Secure Replay evidence."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
from typing import Any


ALGORITHM = "git-tree-diff-sha256-v1"
CANONICAL_ALGORITHM = "canonical-json-sha256-v1"
REGULAR_BLOB_MODES = {"100644", "100755"}


def fail(message: str) -> None:
    print(f"secure replay evidence verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    record: dict[str, Any] = {}
    for key, value in pairs:
        if key in record:
            fail(f"JSON has duplicate key: {key}")
        record[key] = value
    return record


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, json.JSONDecodeError):
        fail("manifest is not readable JSON")
    if not isinstance(value, dict):
        fail("manifest is not a JSON object")
    return value


def git(repository: pathlib.Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        env=os.environ | {"GIT_NO_REPLACE_OBJECTS": "1"},
    )
    if result.returncode != 0:
        fail("required immutable Git object is unavailable")
    return result.stdout


def full_sha(reference: str) -> bool:
    return len(reference) == 40 and all(character in "0123456789abcdef" for character in reference)


def repository_for(path: pathlib.Path) -> pathlib.Path:
    if path.is_symlink() or not path.is_file():
        fail("manifest path is not a current regular non-symlink file")
    result = subprocess.run(
        ["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"],
        capture_output=True,
        env=os.environ | {"GIT_NO_REPLACE_OBJECTS": "1"},
    )
    if result.returncode:
        fail("manifest path is not inside a Git repository")
    return pathlib.Path(result.stdout.decode().strip()).resolve()


def resolve_commit(repository: pathlib.Path, reference: str, label: str) -> str:
    if not full_sha(reference):
        fail(f"{label} must be a full lowercase SHA-1")
    commit = git(repository, "rev-parse", "--verify", f"{reference}^{{commit}}").decode().strip()
    if commit != reference:
        fail(f"{label} does not identify its immutable commit")
    return commit


def safe_path(value: Any) -> str:
    if not isinstance(value, str):
        fail("manifest path is not a string")
    path = pathlib.PurePosixPath(value)
    if not path.parts or path.is_absolute() or value != path.as_posix() or ".." in path.parts:
        fail("manifest path is not a safe repository-relative path")
    return path.as_posix()


def sha256_blob(repository: pathlib.Path, oid: str) -> str:
    return hashlib.sha256(git(repository, "cat-file", "blob", oid)).hexdigest()


def parse_diff(data: bytes) -> dict[str, str]:
    fields = data.split(b"\0")
    if fields[-1:] != [b""] or (len(fields) - 1) % 2:
        fail("immutable name-status output is malformed")
    changed: dict[str, str] = {}
    for index in range(0, len(fields) - 1, 2):
        try:
            status, path = fields[index].decode(), fields[index + 1].decode()
        except UnicodeDecodeError:
            fail("immutable changed path is not UTF-8")
        if status not in {"A", "M", "D"} or path in changed:
            fail("immutable name-status output has an unsafe disposition")
        changed[path] = status
    return changed


def parse_tree(data: bytes) -> dict[str, tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    for item in data.split(b"\0"):
        if not item:
            continue
        try:
            metadata, raw_path = item.split(b"\t", 1)
            mode, kind, oid = metadata.decode().split()
            path = raw_path.decode()
        except (UnicodeDecodeError, ValueError):
            fail("immutable tree output is malformed")
        if path in entries:
            fail("immutable tree has duplicate paths")
        entries[path] = (mode, kind, oid)
    return entries


def manifest_entries(subject: dict[str, Any]) -> dict[str, tuple[str, str | None]]:
    manifest = subject.get("changedFileManifest")
    if not isinstance(manifest, list):
        fail("changed-file manifest is missing")
    expected: dict[str, tuple[str, str | None]] = {}
    for entry in manifest:
        if not isinstance(entry, dict):
            fail("manifest entry is not an object")
        path, status, digest = safe_path(entry.get("path")), entry.get("status"), entry.get("sha256")
        if path in expected:
            fail(f"duplicate manifest path: {path}")
        if status == "present" and isinstance(digest, str) and len(digest) == 64 and all(
            character in "0123456789abcdef" for character in digest
        ):
            expected[path] = (status, digest)
        elif status == "deleted" and digest is None:
            expected[path] = (status, None)
        else:
            fail(f"invalid manifest disposition for: {path}")
    return expected


def canonical_digest(record: dict[str, Any]) -> str:
    payload = dict(record)
    payload.pop("canonicalJsonSha256", None)
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def require_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        fail(f"{label} does not conform to secure-replay-evidence-v2 schema")


def validate_v2_schema(record: dict[str, Any], schema_path: pathlib.Path) -> dict[str, Any]:
    schema = load_json(schema_path)
    if schema.get("$id") != "https://gocode.dev/schemas/secure-replay-evidence-v2.schema.json":
        fail("schema is not secure-replay-evidence-v2")
    keys = {"schemaVersion", "evidenceId", "recordedAt", "subject", "correctiveSuperseding",
            "canonicalJsonDigestAlgorithm", "canonicalJsonSha256", "platform", "toolchains",
            "qualification", "observedResults", "closureValidation", "coverage", "securityReview",
            "markerScan", "sensitiveDataPolicy"}
    require_keys(record, keys, "record")
    if record["schemaVersion"] != 2 or record["evidenceId"] != "secure-replay-desktop-resume-v2":
        fail("record identity is not secure-replay-desktop-resume-v2")
    if record["canonicalJsonDigestAlgorithm"] != CANONICAL_ALGORITHM or not isinstance(record["canonicalJsonSha256"], str):
        fail("canonical JSON digest metadata is invalid")
    if record["canonicalJsonSha256"] != canonical_digest(record):
        fail("canonical JSON SHA-256 mismatch")
    subject = record["subject"]
    if not isinstance(subject, dict):
        fail("subject is missing")
    require_keys(subject, {"sourceBaseCommit", "sourceHeadCommit", "manifestAlgorithm",
                           "manifestSelfExcludedPath", "changedFileManifest", "contractProfileId",
                           "transportProfileId", "contractBundleSha256"}, "subject")
    linkage = record["correctiveSuperseding"]
    if not isinstance(linkage, dict):
        fail("corrective superseding linkage is missing")
    require_keys(linkage, {"supersedesEvidenceId", "originalEvidenceBlobSha1",
                           "originalEvidenceContentSha256", "recoveredSnapshotCommit",
                           "recoveredSnapshotEvidenceBlobSha1"}, "corrective superseding linkage")
    return subject


def verify_legacy(evidence_path: pathlib.Path, expected_blob: str) -> None:
    repository = repository_for(evidence_path.absolute())
    if not full_sha(expected_blob):
        fail("legacy blob must be a full lowercase SHA-1")
    if git(repository, "cat-file", "-t", expected_blob).decode().strip() != "blob":
        fail("legacy evidence object is not a blob")
    if evidence_path.read_bytes() != git(repository, "cat-file", "blob", expected_blob):
        fail("legacy evidence does not match its immutable Git blob")


def verify_v2(evidence_path: pathlib.Path, base_reference: str, head_reference: str, schema_path: pathlib.Path) -> None:
    evidence_path = evidence_path.absolute()
    repository = repository_for(evidence_path)
    record = load_json(evidence_path)
    subject = validate_v2_schema(record, schema_path)
    linkage = record["correctiveSuperseding"]
    base_commit = resolve_commit(repository, base_reference, "base")
    head_commit = resolve_commit(repository, head_reference, "head")
    if subject.get("sourceBaseCommit") != base_commit or subject.get("sourceHeadCommit") != head_commit:
        fail("manifest source commits do not match pinned snapshot")
    if subject.get("manifestAlgorithm") != ALGORITHM:
        fail("manifest algorithm is not immutable snapshot v1")
    if linkage["recoveredSnapshotCommit"] != head_commit:
        fail("corrective recovered snapshot commit does not match pinned head")
    original_blob = linkage["originalEvidenceBlobSha1"]
    recovered_blob = linkage["recoveredSnapshotEvidenceBlobSha1"]
    if not full_sha(original_blob) or not full_sha(recovered_blob):
        fail("corrective linkage requires full lowercase blob SHA-1 values")
    if sha256_blob(repository, original_blob) != linkage["originalEvidenceContentSha256"]:
        fail("corrective original evidence content SHA-256 mismatch")
    excluded = safe_path(subject.get("manifestSelfExcludedPath"))
    expected = manifest_entries(subject)
    if excluded in expected:
        fail("manifest self-exclusion is not exact")
    if subprocess.run(["git", "-C", str(repository), "merge-base", "--is-ancestor", base_commit, head_commit],
                      env=os.environ | {"GIT_NO_REPLACE_OBJECTS": "1"}).returncode:
        fail("source base commit is not an ancestor of source head commit")
    actual = parse_diff(git(repository, "diff", "--name-status", "-z", "--no-renames", base_commit, head_commit, "--"))
    if excluded not in actual:
        fail("manifest self-excluded path is not changed in the historical snapshot")
    actual.pop(excluded)
    if set(expected) != set(actual):
        missing, stale = sorted(set(actual) - set(expected)), sorted(set(expected) - set(actual))
        fail("; ".join(filter(None, [f"unlisted changed paths: {', '.join(missing)}" if missing else "",
                                       f"stale manifest paths: {', '.join(stale)}" if stale else ""])))
    tree = parse_tree(git(repository, "ls-tree", "-r", "-z", head_commit))
    recovered_entry = tree.get(excluded)
    if recovered_entry is None or recovered_entry[2] != recovered_blob:
        fail("corrective recovered snapshot evidence blob does not match Git tree")
    for path, (status, digest) in expected.items():
        disposition, entry = actual[path], tree.get(path)
        if status == "deleted":
            if disposition != "D" or entry is not None:
                fail(f"expected deleted path has invalid historical disposition: {path}")
        elif disposition == "D" or entry is None or entry[0] not in REGULAR_BLOB_MODES or entry[1] != "blob":
            fail(f"historical manifest path is not a regular blob: {path}")
        elif sha256_blob(repository, entry[2]) != digest:
            fail(f"SHA-256 mismatch for: {path}")
    recovered = json.loads(git(repository, "cat-file", "blob", recovered_blob), object_pairs_hook=no_duplicates)
    claim_keys = {"platform", "toolchains", "qualification", "observedResults", "closureValidation",
                  "coverage", "securityReview", "markerScan", "sensitiveDataPolicy"}
    if any(record[key] != recovered.get(key) for key in claim_keys):
        fail("corrective record adds or alters recovered execution claims")
    if subject["changedFileManifest"] != recovered.get("subject", {}).get("changedFileManifest"):
        fail("corrective changed-file manifest differs from recovered snapshot")
