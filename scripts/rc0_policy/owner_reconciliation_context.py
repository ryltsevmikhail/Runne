"""Fail-closed loader for externally owner-controlled reconciliation material."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Callable, Protocol

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.reconciliation import (
    OwnerReconciliationContext,
    OwnerReconciliationContextBlocked,
    PreSignedReconciliationNegative,
)


OWNER_RECONCILIATION_CONTEXT_MANIFEST_SCHEMA_VERSION = (
    "gocode.post-rc0.owner-reconciliation-context-manifest/1"
)
_EXPECTED_CODES = {
    "unregistered_role": "RECONCILIATION_ROLE_UNREGISTERED",
    "subject_substitution": "RECONCILIATION_PRINCIPAL_MISMATCH",
    "account_substitution": "RECONCILIATION_PRINCIPAL_MISMATCH",
    "session_substitution": "RECONCILIATION_PRINCIPAL_MISMATCH",
    "lane_substitution": "RECONCILIATION_PRINCIPAL_MISMATCH",
    "stale": "RECONCILIATION_TRUST_STALE",
    "revoked": "RECONCILIATION_TRUST_REVOKED",
}


class OwnerReconciliationContextProvider(Protocol):
    def load_context(self) -> OwnerReconciliationContext: ...


def _blocked() -> OwnerReconciliationContextBlocked:
    return OwnerReconciliationContextBlocked(
        "BLOCKED(EXTERNAL_RECONCILIATION_AUTHORITY_UNAVAILABLE)"
    )


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hex_digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _external_regular(path: Path, repo_root: Path) -> Path:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise _blocked()
    resolved, root = path.resolve(), repo_root.resolve()
    if resolved == root or root in resolved.parents:
        raise _blocked()
    return resolved


def _read_hashed(path: Path, expected_sha256: str, repo_root: Path) -> tuple[Path, bytes]:
    if not _hex_digest(expected_sha256):
        raise _blocked()
    try:
        resolved = _external_regular(path, repo_root)
        raw = resolved.read_bytes()
    except OSError as error:
        raise _blocked() from error
    if _digest(raw) != expected_sha256:
        raise _blocked()
    return resolved, raw


def _manifest(raw: bytes, context_sha256: str) -> dict[str, object]:
    try:
        value = loads_canonical(raw)
    except ValueError as error:
        raise _blocked() from error
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise _blocked()
    if set(value) != {"schema_version", "context_sha256", "vectors"}:
        raise _blocked()
    if value["schema_version"] != OWNER_RECONCILIATION_CONTEXT_MANIFEST_SCHEMA_VERSION:
        raise _blocked()
    if value["context_sha256"] != context_sha256 or not _hex_digest(value["context_sha256"]):
        raise _blocked()
    vectors = value["vectors"]
    if type(vectors) is not list or len(vectors) != len(_EXPECTED_CODES):
        raise _blocked()
    ids: list[str] = []
    for vector in vectors:
        if type(vector) is not dict or set(vector) != {"vector_id", "raw_sha256", "expected_code"}:
            raise _blocked()
        vector_id, raw_sha256, code = vector["vector_id"], vector["raw_sha256"], vector["expected_code"]
        if type(vector_id) is not str or not _hex_digest(raw_sha256) or _EXPECTED_CODES.get(vector_id) != code:
            raise _blocked()
        ids.append(vector_id)
    if ids != sorted(ids) or set(ids) != set(_EXPECTED_CODES):
        raise _blocked()
    return value


def _context_provider_from_raw(context_raw: bytes) -> Callable[[], OwnerReconciliationContext]:
    if type(context_raw) is not bytes:
        raise TypeError("owner context must be exact bytes")
    try:
        namespace: dict[str, object] = {"__name__": "gocode_owner_reconciliation_context"}
        exec(compile(context_raw, "<hashed-owner-reconciliation-context>", "exec"), namespace)
        provider = namespace.get("load_context")
        if not callable(provider):
            raise _blocked()
    except OwnerReconciliationContextBlocked:
        raise
    except Exception as error:
        raise _blocked() from error
    return provider


def _import_context(context_raw: bytes) -> OwnerReconciliationContext:
    try:
        context = _context_provider_from_raw(context_raw)()
    except OwnerReconciliationContextBlocked:
        raise
    except Exception as error:
        raise _blocked() from error
    if type(context) is not OwnerReconciliationContext:
        raise _blocked()
    return context


def _validate_context(context: OwnerReconciliationContext, manifest: dict[str, object]) -> None:
    if type(context.raw) is not bytes or type(context.now_epoch_seconds) is not int or isinstance(context.now_epoch_seconds, bool):
        raise _blocked()
    if not callable(context.verify_signature) or type(context.negative_vectors) is not tuple:
        raise _blocked()
    vectors = manifest["vectors"]
    expected = {item["vector_id"]: item for item in vectors}
    if len(context.negative_vectors) != len(expected):
        raise _blocked()
    actual_ids: list[str] = []
    for vector in context.negative_vectors:
        if type(vector) is not PreSignedReconciliationNegative or type(vector.raw) is not bytes:
            raise _blocked()
        expected_item = expected.get(vector.vector_id)
        if expected_item is None or _digest(vector.raw) != expected_item["raw_sha256"] or vector.expected_code != expected_item["expected_code"]:
            raise _blocked()
        actual_ids.append(vector.vector_id)
    if actual_ids != sorted(actual_ids) or set(actual_ids) != set(expected):
        raise _blocked()


def load_owner_reconciliation_context(
    context_path: Path, expected_sha256: str, negative_manifest_path: Path,
    negative_manifest_sha256: str, repo_root: Path,
) -> OwnerReconciliationContext:
    """Load only externally hashed context and independent negative receipts."""
    try:
        _, context_raw = _read_hashed(context_path, expected_sha256, repo_root)
        _, manifest_raw = _read_hashed(negative_manifest_path, negative_manifest_sha256, repo_root)
        manifest = _manifest(manifest_raw, _digest(context_raw))
        context = _import_context(context_raw)
        _validate_context(context, manifest)
        return context
    except OwnerReconciliationContextBlocked:
        raise
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise _blocked() from error


def load_context_from_environment(repo_root: Path) -> OwnerReconciliationContext:
    """Convenience boundary that remains blocked when owner material is absent."""
    try:
        return load_owner_reconciliation_context(
            Path(os.environ["GOCODE_POST_RC0_RECONCILIATION_CONTEXT_PATH"]),
            os.environ["GOCODE_POST_RC0_RECONCILIATION_CONTEXT_SHA256"],
            Path(os.environ["GOCODE_POST_RC0_RECONCILIATION_NEGATIVE_MANIFEST_PATH"]),
            os.environ["GOCODE_POST_RC0_RECONCILIATION_NEGATIVE_MANIFEST_SHA256"], repo_root,
        )
    except KeyError as error:
        raise _blocked() from error
