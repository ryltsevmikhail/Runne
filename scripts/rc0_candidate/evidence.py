"""Nine-blob fixture evidence validation and atomic local construction."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from scripts.rc0_policy.bindings import EVIDENCE_FILES, validate_record_bindings
from scripts.rc0_policy.canonical import StrictJSONError, canonical_bytes
from scripts.rc0_policy.model import FixtureValidationError, parse_checksums_text
from scripts.rc0_policy.schemas import validate_schema

from .source import validate_fixture_evidence_commit

_SHA = re.compile(r"[0-9a-f]{40}")
_SCHEMAS = {
    "candidate-record.json": "gocode.rc0.schema.candidate-record/3",
    "source-gate-results.json": "gocode.rc0.schema.source-gate-results/3",
    "test-inventory.json": "gocode.rc0.schema.test-inventory/3",
    "security-validation.json": "gocode.rc0.schema.security-validation/3",
    "documentation-validation.json": "gocode.rc0.schema.documentation-validation/3",
    "fail-closed-disposition.json": "gocode.rc0.schema.fail-closed-disposition/3",
    "artifact-inventory.json": "gocode.rc0.schema.artifact-inventory/3",
    "sbom.spdx.json": "gocode.rc0.schema.sbom-spdx-2.3/3",
}
_CREDENTIAL_KEYS = ("password", "secret", "token", "credential", "private_key", "api_key")


class EvidenceConstructionError(ValueError):
    """Fixture evidence cannot be safely constructed."""

@dataclass(frozen=True)
class EvidenceBuildResult:
    directory: Path
    blobs: Mapping[str, bytes]
    evidence_bundle_digest: str

def validate_fixture_evidence_entries(
    source_sha: str, entries: Mapping[str, Mapping[str, Any]]
) -> tuple[str, ...]:
    errors: list[str] = []
    if _SHA.fullmatch(source_sha) is None:
        errors.append("evidence root source SHA is not canonical lower-case hex")
    if set(entries) != set(EVIDENCE_FILES) or len(entries) != len(EVIDENCE_FILES):
        errors.append("evidence diff must add exactly the nine named direct children")
    for name, entry in entries.items():
        if name not in EVIDENCE_FILES or "/" in name or "\\" in name:
            errors.append(f"unexpected evidence path: {name}")
            continue
        if entry.get("mode") != "100644" or entry.get("type") != "blob":
            errors.append(f"evidence entry is not a regular 100644 blob: {name}")
        if not isinstance(entry.get("data"), bytes):
            errors.append(f"evidence entry data is not bytes: {name}")
    return tuple(errors)


def evidence_bundle_digest(source_sha: str, blobs: Mapping[str, bytes]) -> str:
    entries = {
        name: {"mode": "100644", "type": "blob", "data": data}
        for name, data in blobs.items()
    }
    diagnostics = validate_fixture_evidence_entries(source_sha, entries)
    if diagnostics:
        raise EvidenceConstructionError("; ".join(diagnostics))
    prefix = f"docs/evidence/rc0-candidates/{source_sha}/"
    digest = hashlib.sha256(b"GOCODE_RC0_EVIDENCE_V1\0")
    for name in sorted(blobs, key=lambda item: (prefix + item).encode("utf-8")):
        path = (prefix + name).encode("utf-8")
        data = blobs[name]
        digest.update(struct.pack(">I", len(path)))
        digest.update(path)
        digest.update(struct.pack(">Q", len(data)))
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def _credential_diagnostics(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = key.casefold()
            if any(token in lowered for token in _CREDENTIAL_KEYS):
                errors.append(f"credential-shaped field is forbidden at {path}.{key}")
            errors.extend(_credential_diagnostics(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_credential_diagnostics(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        parsed = urlsplit(value) if "://" in value else None
        credential_url = parsed is not None and (
            parsed.username is not None or parsed.password is not None
        )
        credential_prefix = value.startswith(
            ("-----BEGIN PRIVATE KEY", "Bearer ", "ghp_", "github_pat_", "sk-")
        )
        if credential_url or credential_prefix:
            errors.append(f"credential material is forbidden at {path}")
    return errors


def _self_reference_diagnostics(records: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for container, field in (
        (records["artifact-inventory.json"], "artifacts"),
        (records["checksums.txt"], "artifacts"),
        (records["sbom.spdx.json"], "artifact_bindings"),
    ):
        for item in container.get(field, []):
            if isinstance(item, dict) and str(item.get("relative_path", "")).startswith("docs/evidence/"):
                errors.append("candidate artifact inventory cannot reference evidence blobs")
    return errors


def _prepare_blobs(records: Mapping[str, Any]) -> tuple[str, dict[str, bytes]]:
    if set(records) != set(EVIDENCE_FILES) or len(records) != len(EVIDENCE_FILES):
        raise EvidenceConstructionError("construction requires exactly the nine candidate-owned blobs")
    normalized: dict[str, Any] = {}
    blobs: dict[str, bytes] = {}
    diagnostics: list[str] = []
    for name in EVIDENCE_FILES:
        value = records[name]
        if name == "checksums.txt":
            if not isinstance(value, bytes):
                diagnostics.append("checksums.txt must be caller-supplied canonical bytes")
                continue
            try:
                parsed = parse_checksums_text(value)
            except FixtureValidationError as error:
                diagnostics.append(str(error))
                continue
            normalized[name] = parsed
            blobs[name] = value
            diagnostics.extend(validate_schema(parsed, "gocode.rc0.schema.checksums-text/3"))
            if any(not item["relative_path"].isascii() for item in parsed["artifacts"]):
                diagnostics.append("checksums artifact paths must be ASCII")
        else:
            if not isinstance(value, dict):
                diagnostics.append(f"{name} must be an object")
                continue
            diagnostics.extend(_credential_diagnostics(value))
            diagnostics.extend(validate_schema(value, _SCHEMAS[name]))
            try:
                blobs[name] = canonical_bytes(value)
            except StrictJSONError as error:
                diagnostics.append(f"{name}: {error}")
                continue
            normalized[name] = value
    if diagnostics:
        raise EvidenceConstructionError("; ".join(diagnostics))
    diagnostics.extend(validate_record_bindings(normalized))
    source_sha = normalized["candidate-record.json"].get("candidate_source_revision")
    if not isinstance(source_sha, str) or _SHA.fullmatch(source_sha) is None:
        diagnostics.append("candidate source SHA is not canonical lower-case hex")
    else:
        diagnostics.extend(_self_reference_diagnostics(normalized))
    if diagnostics:
        raise EvidenceConstructionError("; ".join(diagnostics))
    return source_sha, blobs


def _safe_output_root(output_root: Path, checkout_root: Path) -> Path:
    output_root = Path(output_root)
    checkout_root = Path(checkout_root)
    if output_root.is_symlink() or not output_root.is_dir():
        raise EvidenceConstructionError("output root must be an existing real directory")
    resolved = output_root.resolve()
    checkout = checkout_root.resolve()
    if resolved == checkout or resolved.is_relative_to(checkout):
        raise EvidenceConstructionError("evidence output root must be outside the checkout")
    metadata = resolved.stat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise EvidenceConstructionError("evidence output root must be owner-private")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise EvidenceConstructionError("evidence output root must be owner-owned")
    return resolved


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def build_fixture_evidence(
    records: Mapping[str, Any], output_root: Path, checkout_root: Path
) -> EvidenceBuildResult:
    """Validate then atomically publish nine owner-private fixture blobs."""
    source_sha, blobs = _prepare_blobs(records)
    root = _safe_output_root(output_root, checkout_root)
    final = root / source_sha
    if final.exists() or final.is_symlink():
        raise EvidenceConstructionError("evidence source directory already exists")
    lock = root / f".{source_sha}.construction-lock"
    lock_descriptor: int | None = None
    temporary: Path | None = None
    try:
        lock_descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        temporary = Path(tempfile.mkdtemp(prefix=f".{source_sha}.", dir=root))
        os.chmod(temporary, 0o700)
        for name in EVIDENCE_FILES:
            _write_private(temporary / name, blobs[name])
        directory_descriptor = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        if final.exists() or final.is_symlink():
            raise EvidenceConstructionError("evidence source directory collision")
        os.rename(temporary, final)
        temporary = None
        root_descriptor = os.open(root, os.O_RDONLY)
        try:
            os.fsync(root_descriptor)
        finally:
            os.close(root_descriptor)
    except (FileExistsError, OSError) as error:
        if isinstance(error, EvidenceConstructionError):
            raise
        raise EvidenceConstructionError("atomic evidence construction failed") from error
    finally:
        if temporary is not None:
            shutil.rmtree(temporary)
        if lock_descriptor is not None:
            os.close(lock_descriptor)
        try:
            lock.unlink()
        except FileNotFoundError:
            pass
    digest = evidence_bundle_digest(source_sha, blobs)
    return EvidenceBuildResult(final, dict(blobs), digest)
