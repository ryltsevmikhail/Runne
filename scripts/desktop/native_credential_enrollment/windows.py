"""Windows Credential Manager evidence policy.

The accepted isolation class is owner/logon-session scoped. PID, path and
same-token crafted replacement claims are never accepted as authority.
"""
from __future__ import annotations

from .macos import TUPLE_FIELDS, _forbidden_field_errors, _sha256, tuple_digest

REQUIRED_SELECTORS = frozenset({
    "clean_install", "n_to_n_plus_1", "rollback", "mixed_child_manifest_denied",
    "reparse_point_denied", "hardlink_denied", "retained_handle_pid_reuse_denied",
    "package_skew_denied", "file_id_post_spawn_image_skew_denied",
    "third_process_broker_denied", "owner_logon_session_isolation",
    "observable_absence_metadata_mismatch_fenced", "pair_create_readback", "rotation",
    "revoke_fence_delete", "crash_recovery", "replay_denied", "local_verify_no_network",
    "remote_verify_after_local",
})


def validate_row(row: object) -> list[str]:
    if not isinstance(row, dict):
        return ["row is not an object"]
    errors: list[str] = []
    required = {"platform", "version", "architecture", "package_format", "disposition", "isolation_class", "tuple", "native_store", "runner", "selectors"}
    if set(row) != required:
        errors.append("row fields are not exact")
    if row.get("platform") != "windows" or row.get("version") != "10-22H2":
        errors.append("row is not Windows 10 22H2")
    if row.get("architecture") != "x86_64" or row.get("package_format") != "nsis":
        errors.append("row package target is not admitted")
    if row.get("disposition") != "verified":
        errors.append("row disposition is not verified")
    if row.get("isolation_class") != "owner_session_scoped":
        errors.append("Windows isolation must be owner_session_scoped")
    errors.extend(_tuple_errors(row.get("tuple")))
    errors.extend(_store_errors(row.get("native_store")))
    errors.extend(_runner_errors(row.get("runner")))
    errors.extend(_selector_errors(row.get("selectors")))
    errors.extend(_forbidden_field_errors(row))
    return errors


def _tuple_errors(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != {*TUPLE_FIELDS, "tuple_sha256"}:
        return ["release tuple fields are not exact"]
    if any(not _sha256(value.get(field)) for field in TUPLE_FIELDS):
        return ["release tuple digest is invalid"]
    return [] if value.get("tuple_sha256") == tuple_digest(value) else ["release tuple binding mismatches"]


def _store_errors(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != {"credential_manager", "logon_session"}:
        return ["Credential Manager session evidence is incomplete"]
    if value.get("credential_manager") != "verified" or value.get("logon_session") != "verified":
        return ["mock or absent Credential Manager evidence is rejected"]
    return []


def _runner_errors(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != {"workflow_run_id", "attestation_verified"}:
        return ["runner evidence fields are not exact"]
    if value.get("attestation_verified") is not True:
        return ["runner attestation is not verified"]
    return [] if isinstance(value.get("workflow_run_id"), str) and value["workflow_run_id"] else ["runner workflow identity is missing"]


def _selector_errors(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != REQUIRED_SELECTORS:
        return ["lifecycle selector set is incomplete"]
    for name, item in value.items():
        if not isinstance(item, dict) or item.get("status") not in {"verified", "unsupported"}:
            return [f"selector {name} is not verified or unsupported"]
        allowed = {"status", "network_attempts"} if name == "local_verify_no_network" else {"status", "local_verification", "retry_count"} if name == "remote_verify_after_local" else {"status"}
        if set(item) != allowed:
            return [f"selector {name} fields are not exact"]
    local, remote = value["local_verify_no_network"], value["remote_verify_after_local"]
    if local.get("status") != "verified" or local.get("network_attempts") != 0:
        return ["local verification must be verified without network"]
    if remote.get("local_verification") != "verified" or remote.get("retry_count") != 0:
        return ["remote verification lacks current local success or has retries"]
    return []
