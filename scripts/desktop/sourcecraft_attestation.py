"""Offline-only SourceCraft attestation bundle schema reference.

This module is intentionally not imported by production verification. External
SourceCraft proof is accepted only from the fixed pre-provisioned verifier in
``capability_manifest_impl.io``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping


def _load(path: Path) -> object:
    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)


def validate_offline(subject: Path, bundle: Path, policy: Mapping[str, str], source_digest: str) -> dict[str, object] | None:
    """Validate shape and subject digest without making an external trust claim."""

    try:
        value = _load(bundle)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    required = {"schema_version", "repository", "workflow", "source_ref", "source_digest", "subject", "predicate", "signer"}
    if not isinstance(value, dict) or set(value) != required:
        return None
    if any(value[key] != policy.get(key) for key in ("repository", "workflow", "source_ref")) or value["source_digest"] != source_digest:
        return None
    subject_value, signer, predicate = value["subject"], value["signer"], value["predicate"]
    if value["schema_version"] != "sourcecraft-attestation.v1" or not isinstance(subject_value, dict) or set(subject_value) != {"sha256"} or not isinstance(subject_value["sha256"], str) or not isinstance(predicate, dict):
        return None
    if not isinstance(signer, dict) or set(signer) != {"id", "external_proof"} or signer["id"] != policy.get("signer") or signer["external_proof"] is not True:
        return None
    return predicate if subject_value["sha256"] == hashlib.sha256(subject.read_bytes()).hexdigest() else None
