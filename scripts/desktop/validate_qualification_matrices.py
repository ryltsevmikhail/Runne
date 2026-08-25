#!/usr/bin/env python3
"""Validate the structural Desktop quality matrices without claiming evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

try:
    from scripts.desktop.capability_manifest_impl.io import load_json, protected_policy, verify_attestation
except ModuleNotFoundError:
    from capability_manifest_impl.io import load_json, protected_policy, verify_attestation


MATRICES = {
    "docs/desktop/06-design-system/ACCESSIBILITY_TEST_MATRIX.md": (
        "| Check | Automated | Manual |",
    ),
    "docs/desktop/06-design-system/LOCALIZATION.md": (
        "v1 product locales: Russian and English.",
    ),
    "docs/desktop/07-testing/SECURITY_ABUSE_CASES.md": (
        "| ID | Attack | Expected result |",
    ),
    "docs/desktop/03-desktop/ERROR_AND_DEGRADED_STATE_MATRIX.md": (
        "| Condition | Visible state | Allowed | Primary recovery |",
    ),
}
MARKER_KEYS = {"schema_version", "disposition", "evidence_ref", "p0_p1_disposition"}
DISPOSITIONS = {"blocked", "unverified", "verified"}
FORBIDDEN_P0_P1 = {"accepted", "approved", "waived", "waiver"}
EVIDENCE_ROOT = "docs/evidence/desktop-qualification"
EVIDENCE_KEYS = {
    "schema_version",
    "matrix_path",
    "matrix_sha256",
    "source_ref",
    "source_digest",
    "producer",
    "provenance_ref",
    "p0_p1_disposition",
    "results",
}
EVIDENCE_RESULT_KEYS = {"row_id", "disposition", "result"}
SOURCE_SHA = re.compile(r"[0-9a-f]{40}")
SOURCE_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9._/-]+")
SHA256 = re.compile(r"[0-9a-f]{64}")
EXTERNAL_PROVENANCE = re.compile(r"(?:https://|attestation://)[^\s]+")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key}")
        value[key] = item
    return value


def load_json_from_text(text: str) -> object:
    return json.loads(text, object_pairs_hook=_unique_object)


def _qualification_marker(content: str) -> dict[str, object] | None:
    if not content.startswith("---\n"):
        return None
    front_matter = content.split("\n---\n", 1)
    if len(front_matter) != 2:
        return None
    for line in front_matter[0].splitlines()[1:]:
        if line.startswith("qualification_evidence:"):
            try:
                marker = load_json_from_text(line.partition(":")[2].strip())
            except (ValueError, json.JSONDecodeError):
                return None
            return marker if isinstance(marker, dict) else None
    return None


def _validate_evidence_record(
    root: Path,
    matrix_path: Path,
    evidence_ref: str,
    expected_source_ref: str | None,
    expected_source_digest: str | None,
) -> list[str]:
    errors: list[str] = []
    evidence_path = (root / evidence_ref).resolve()
    if evidence_path == matrix_path.resolve():
        return [f"{matrix_path.name}: qualification evidence_ref must be distinct from matrix"]
    expected_ref = f"{EVIDENCE_ROOT}/{matrix_path.stem}.json"
    if evidence_ref != expected_ref:
        return [f"{matrix_path.name}: qualification evidence_ref must be canonical"]
    try:
        evidence_path.relative_to(root.resolve())
    except ValueError:
        return [f"{matrix_path.name}: qualification evidence_ref is outside root"]
    canonical_path = root.resolve() / expected_ref
    if canonical_path.resolve() != canonical_path:
        return [f"{matrix_path.name}: canonical qualification evidence must not be a symlink"]
    if not canonical_path.is_file():
        return [f"{matrix_path.name}: qualification evidence_ref is missing"]
    try:
        value = load_json(canonical_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return [f"{matrix_path.name}: qualification evidence is not structured JSON"]
    if not isinstance(value, dict) or set(value) != EVIDENCE_KEYS:
        return [f"{matrix_path.name}: qualification evidence has invalid schema"]
    expected_matrix = matrix_path.relative_to(root).as_posix()
    if value["schema_version"] != "desktop-qualification-evidence.v1":
        errors.append(f"{matrix_path.name}: qualification evidence has invalid schema")
    if value["matrix_path"] != expected_matrix:
        errors.append(f"{matrix_path.name}: qualification evidence matrix path mismatch")
    expected_digest = hashlib.sha256(matrix_path.read_bytes()).hexdigest()
    if value["matrix_sha256"] != expected_digest or SHA256.fullmatch(str(value["matrix_sha256"])) is None:
        errors.append(f"{matrix_path.name}: qualification evidence matrix_sha256 mismatch")
    if not isinstance(value["source_ref"], str) or SOURCE_REF.fullmatch(value["source_ref"]) is None:
        errors.append(f"{matrix_path.name}: qualification evidence source_ref must be an immutable protected ref")
    elif expected_source_ref is not None and value["source_ref"] != expected_source_ref:
        errors.append(f"{matrix_path.name}: qualification evidence source_ref does not match protected ref")
    if not isinstance(value["source_digest"], str) or SOURCE_SHA.fullmatch(value["source_digest"]) is None:
        errors.append(f"{matrix_path.name}: qualification evidence source_digest must be a full SHA")
    elif expected_source_digest is not None and value["source_digest"] != expected_source_digest:
        errors.append(f"{matrix_path.name}: qualification evidence source_digest does not match candidate")
    if value["producer"] != "protected-runner":
        errors.append(f"{matrix_path.name}: qualification evidence producer must be protected-runner")
    if not isinstance(value["provenance_ref"], str) or EXTERNAL_PROVENANCE.fullmatch(value["provenance_ref"]) is None:
        errors.append(f"{matrix_path.name}: qualification evidence provenance_ref must be external")
    if value["p0_p1_disposition"] != "verified":
        errors.append(f"{matrix_path.name}: qualification evidence P0/P1 disposition is not verified")
    results = value["results"]
    if not isinstance(results, list) or [item.get("row_id") for item in results if isinstance(item, dict)] != ["P0", "P1"]:
        errors.append(f"{matrix_path.name}: qualification evidence results must be exactly P0 and P1")
        return errors
    for result in results:
        if not isinstance(result, dict) or set(result) != EVIDENCE_RESULT_KEYS:
            errors.append(f"{matrix_path.name}: qualification evidence result is malformed")
            continue
        row_id = result["row_id"]
        if result["disposition"] != "verified":
            errors.append(f"{matrix_path.name}: qualification evidence result is not verified")
        if not isinstance(result["result"], str) or not result["result"].strip():
            errors.append(f"{matrix_path.name}: qualification evidence result is empty")
    return errors


def _verify_external_evidence(
    root: Path,
    matrix_path: Path,
    source_ref: str | None,
    source_digest: str | None,
    policy: dict[str, str] | None,
) -> list[str]:
    if not isinstance(source_ref, str) or SOURCE_REF.fullmatch(source_ref) is None:
        return [f"{matrix_path.name}: external verification requires an immutable protected source_ref"]
    if not isinstance(source_digest, str) or SOURCE_SHA.fullmatch(source_digest) is None:
        return [f"{matrix_path.name}: external verification requires a full source_digest SHA"]
    if policy is None or policy.get("source_ref") != source_ref:
        return [f"{matrix_path.name}: external verification policy is unavailable or mismatched"]
    evidence_path = root.resolve() / EVIDENCE_ROOT / f"{matrix_path.stem}.json"
    bundle = evidence_path.with_name(evidence_path.name + ".intoto.jsonl")
    if not bundle.is_file() or bundle.resolve() != bundle:
        return [f"{matrix_path.name}: qualification evidence attestation bundle is missing or invalid"]
    if verify_attestation(evidence_path, bundle, policy, source_digest) is None:
        return [f"{matrix_path.name}: qualification evidence attestation verification failed"]
    return []


def _validate_marker(
    root: Path,
    path: Path,
    marker: dict[str, object] | None,
    *,
    verify_external: bool,
    source_ref: str | None,
    source_digest: str | None,
    policy: dict[str, str] | None,
) -> list[str]:
    if marker is None or set(marker) != MARKER_KEYS:
        return [f"{path.name}: invalid qualification_evidence marker"]
    if marker["schema_version"] != "desktop-qualification-matrix.v1":
        return [f"{path.name}: unsupported qualification_evidence schema"]
    disposition = marker["disposition"]
    p0_p1 = marker["p0_p1_disposition"]
    evidence_ref = marker["evidence_ref"]
    errors: list[str] = []
    if disposition not in DISPOSITIONS:
        errors.append(f"{path.name}: invalid qualification disposition {disposition}")
    if disposition == "verified" and p0_p1 != "verified":
        errors.append(f"{path.name}: verified qualification requires verified P0/P1 disposition")
    if p0_p1 in FORBIDDEN_P0_P1:
        errors.append(f"{path.name}: forbidden P0/P1 disposition {p0_p1}")
    elif p0_p1 not in DISPOSITIONS:
        errors.append(f"{path.name}: invalid P0/P1 disposition {p0_p1}")
    if evidence_ref is not None and (not isinstance(evidence_ref, str) or not evidence_ref):
        errors.append(f"{path.name}: evidence_ref must be null or a relative path")
    if disposition == "verified" and evidence_ref is None:
        errors.append(f"{path.name}: verified disposition requires evidence_ref")
    if p0_p1 == "verified" and evidence_ref is None:
        errors.append(f"{path.name}: verified P0/P1 disposition requires evidence_ref")
    if isinstance(evidence_ref, str) and evidence_ref:
        errors.extend(_validate_evidence_record(root, path, evidence_ref, source_ref, source_digest))
    if (disposition == "verified" or p0_p1 == "verified") and not verify_external:
        errors.append(f"{path.name}: qualification evidence requires external verification")
    elif (disposition == "verified" or p0_p1 == "verified") and not errors:
        errors.extend(_verify_external_evidence(root, path, source_ref, source_digest, policy))
    return errors


def validate_matrices(
    root: Path,
    *,
    verify_external: bool = False,
    source_ref: str | None = None,
    source_digest: str | None = None,
    attestation_policy: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    policy = attestation_policy if attestation_policy is not None else protected_policy()
    for relative_path, markers in MATRICES.items():
        path = root / relative_path
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            errors.append(f"{path.name}: missing matrix")
            continue
        errors.extend(
            _validate_marker(
                root,
                path,
                _qualification_marker(content),
                verify_external=verify_external,
                source_ref=source_ref,
                source_digest=source_digest,
                policy=policy,
            )
        )
        for marker in markers:
            if marker not in content:
                errors.append(f"{path.name}: missing matrix table {marker}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--verify-external", action="store_true")
    parser.add_argument("--source-ref")
    parser.add_argument("--source-digest")
    args = parser.parse_args(argv)
    if (args.source_ref or args.source_digest) and not args.verify_external:
        parser.error("--source-ref/--source-digest require --verify-external")
    if args.verify_external and (not args.source_ref or not args.source_digest):
        parser.error("--verify-external requires --source-ref and --source-digest")
    errors = validate_matrices(args.root, verify_external=args.verify_external, source_ref=args.source_ref, source_digest=args.source_digest)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Desktop qualification matrices passed structurally.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
