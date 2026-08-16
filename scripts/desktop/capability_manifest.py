#!/usr/bin/env python3
"""Validate and score the immutable Desktop v1 capability registry."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

if __package__:
    from .capability_manifest_impl.io import canonical_json, clean_source_paths, evidence_only_difference, is_sha256, load_json, protected_policy, resolve_commit, sha256_file, verify_attestation
    from .capability_manifest_impl.scoring import QualificationContext, evaluate
    from .capability_manifest_impl.validation import validate_repository
else:
    from capability_manifest_impl.io import canonical_json, clean_source_paths, evidence_only_difference, is_sha256, load_json, protected_policy, resolve_commit, sha256_file, verify_attestation
    from capability_manifest_impl.scoring import QualificationContext, evaluate
    from capability_manifest_impl.validation import validate_repository


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STATUS = ROOT / "docs/evidence/desktop-v1-capability-status-v2.json"
DEFAULT_DEFINITION = ROOT / "docs/profiles/desktop-v1-capabilities-v1.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--source-ref")
    score = commands.add_parser("score")
    score.add_argument("--status", type=Path, default=DEFAULT_STATUS)
    score.add_argument("--status-provenance", type=Path)
    score.add_argument("--source-ref")
    score.add_argument("--verify-provenance", action="store_true")
    score.add_argument("--format", choices=("json", "text"), default="text")
    args = parser.parse_args(argv)
    if args.command == "validate":
        errors = validate_repository(ROOT, verify_source_ref=args.source_ref)
        print(json.dumps({"valid": not errors, "errors": list(errors)}, sort_keys=True))
        return 0 if not errors else 1
    return _score(args)


def _score(args: argparse.Namespace) -> int:
    errors = validate_repository(ROOT, verify_source_ref=args.source_ref, status_path=args.status)
    if errors:
        print(json.dumps({"valid": False, "errors": list(errors)}, sort_keys=True))
        return 1
    definition = load_json(DEFAULT_DEFINITION)
    status = load_json(args.status)
    qualification = _qualification(args, definition)
    evaluation = evaluate(definition, status, qualification)
    value = {
        "scoreBps": evaluation.score_bps,
        "capabilityStages": list(evaluation.capability_stages),
        "fullyQualified": evaluation.fully_qualified,
        "blockers": list(evaluation.blockers),
    }
    print(json.dumps(value, sort_keys=True) if args.format == "json" else value)
    return 0


def _qualification(args: argparse.Namespace, definition: object) -> QualificationContext | None:
    if not args.verify_provenance or not args.source_ref or args.status_provenance is None:
        return None
    try:
        status = load_json(args.status)
        policy = protected_policy()
        if not isinstance(status, dict) or policy is None or os.environ.get("GOCODE_DESKTOP_CAPABILITY_TRUSTED_STATUS_SHA256") != sha256_file(args.status):
            return None
        commit = resolve_commit(ROOT, args.source_ref)
        if not evidence_only_difference(ROOT, policy["source_ref"], commit):
            return None
        if verify_attestation(args.status, args.status_provenance, policy, commit) is None: return None
        trusted = _trusted_gates(definition, status, args.status.parent, policy, commit)
        if trusted is None: return None
        return QualificationContext(
            str(status["canonical_source_content_sha256"]), args.source_ref, clean_source_paths(ROOT), sha256_file(args.status), trusted,
        )
    except (OSError, ValueError, subprocess.CalledProcessError):
        return None


def _trusted_gates(definition: object, status: dict[str, object], evidence_root: Path, policy: dict[str, str], commit: str) -> tuple[str, ...] | None:
    """Accept only independently Sigstore-verified, exact closed gate subjects."""

    trusted: list[str] = []
    for row in status.get("gates", []):
        if not isinstance(row, dict) or row.get("disposition") != "verified": continue
        evidence_id = row.get("evidence_ref")
        path = evidence_root / evidence_id if isinstance(evidence_id, str) else None
        if not isinstance(path, Path) or path.parent != evidence_root or not path.is_file(): return None
        predicate = verify_attestation(path, Path(f"{path}.intoto.jsonl"), policy, commit)
        if not _gate_predicate(predicate, path, definition, status, row): return None
        trusted.append(str(row["gate_id"]))
    return tuple(trusted)


def _gate_predicate(predicate: object, path: Path, definition: object, status: dict[str, object], row: dict[str, object]) -> bool:
    keys = {"schema_version", "kind", "gate_id", "canonical_source_content_sha256", "definition_sha256", "selector_list_sha256", "toolchain_identity", "runner_identity", "artifacts", "tests"}
    proof = row.get("provenance")
    evidence = load_json(path)
    gate_kinds = _gate_kinds(definition)
    gate_id = evidence.get("gate_id") if isinstance(evidence, dict) else None
    if not isinstance(predicate, dict) or not isinstance(evidence, dict) or set(evidence) != keys or evidence.get("schema_version") != "desktop-v1-gate-evidence.v1" or gate_kinds is None or not isinstance(gate_id, str) or gate_id not in gate_kinds or evidence.get("kind") != gate_kinds[gate_id] or gate_id != row.get("gate_id") or not isinstance(proof, dict): return False
    if evidence.get("canonical_source_content_sha256") != status.get("canonical_source_content_sha256") or evidence.get("definition_sha256") != status.get("definition_sha256") or evidence.get("selector_list_sha256") != status.get("selector_list_sha256") or evidence.get("toolchain_identity") != status.get("toolchain_identity") or evidence.get("runner_identity") != status.get("runner_identity"): return False
    if proof.get("subject_sha256") != sha256_file(path) or proof.get("predicate_sha256") != hashlib.sha256(canonical_json(predicate)).hexdigest(): return False
    if not all(isinstance(rows, list) and rows and all(isinstance(item, dict) and set(item) == {"sha256"} and is_sha256(item["sha256"]) for item in rows) for rows in (evidence["artifacts"], evidence["tests"])): return False
    return True


def _gate_kinds(definition: object) -> dict[str, str] | None:
    if not isinstance(definition, dict): return None
    rows = definition.get("gates")
    if not isinstance(rows, list): return None
    result: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict): return None
        gate_id, kind = row.get("id"), row.get("kind")
        if not isinstance(gate_id, str) or not isinstance(kind, str) or gate_id in result: return None
        result[gate_id] = kind
    return result


if __name__ == "__main__":
    sys.exit(main())
