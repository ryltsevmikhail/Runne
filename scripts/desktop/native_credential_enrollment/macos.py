"""MacOS-only structural checks for credential enrollment evidence.

This module validates redacted receipts only. It cannot qualify a package or
turn on a runtime capability; that decision remains with protected CI and the
signed package admission boundary.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from .evidence_io import shape_errors
from .macos_bindings import ADDITIONAL_SELECTORS, DEPLOYMENT, canonical_digest, deployment_errors
from .macos_receipts import CANARY_DIGEST, code_identity_errors, selector_errors

ARCHITECTURES = frozenset({"arm64"})
REQUIRED_SELECTORS = frozenset({
    "clean_install", "n_to_n_plus_1", "rollback", "mixed_child_manifest_denied",
    "symlink_denied", "hardlink_denied", "pid_reuse_denied", "package_skew_denied",
    "post_spawn_executable_image_skew_denied", "post_spawn_codesign_skew_denied",
    "unsigned_package_denied", "ad_hoc_signature_denied", "keychain_executable_acl_denied",
    "third_process_broker_denied", "pair_create_readback", "rotation",
    "revoke_fence_delete", "crash_recovery", "replay_denied", "local_verify_no_network",
    "remote_verify_after_local",
    "standalone_writer_denied", "standalone_daemon_denied", "wrong_peer_denied",
    "kill_before_service_consume", "kill_after_service_consume",
    "kill_before_native_effect", "kill_after_native_effect",
    "kill_before_readback", "kill_after_readback", "kill_before_reply",
    "kill_after_reply", "kill_before_lifecycle_cas", "kill_after_lifecycle_cas",
    "stored_attributes_verified", "service_restart_persistence",
    "duplicate_version_denied", "account_only_mismatch_denied",
}) | ADDITIONAL_SELECTORS
BASE_TUPLE_FIELDS = (
    "desktop_sha256", "writer_sha256", "daemon_sha256", "contract_sha256",
    "candidate_sha256",
)
TUPLE_FIELDS = (
    "desktop_sha256", "writer_sha256", "daemon_sha256", "service_sha256",
    "launch_agent_plist_sha256", "entitlements_sha256", "provisioning_sha256",
    "protocol_sha256", "contract_sha256", "candidate_sha256",
    "release_tuple_v3_sha256", "deployment_sha256",
    "desktop_code_identity_sha256", "writer_code_identity_sha256",
    "daemon_code_identity_sha256", "service_code_identity_sha256",
)
ROW_FIELDS = {
    "platform", "architecture", "os_version", "disposition", "tuple", "signing",
    "code_identities", "runner", "native_store", "artifact_scan", "selectors", "deployment",
}
TEAM_ID = "758F9Z45SR"
APPLICATION_IDENTIFIERS = {
    "desktop": f"{TEAM_ID}.com.runne.desktop",
    "service": f"{TEAM_ID}.com.runne.credential-service",
}
CODE_IDENTIFIERS = {
    "desktop": "com.runne.desktop", "writer": "runne", "daemon": "runned",
    "service": "com.runne.credential-service",
}
NATIVE_STORE = {
    "access_group": f"{TEAM_ID}.com.runne.credential-service",
    "data_protection_keychain": True,
    "accessibility": "when_unlocked_this_device_only",
    "synchronizable": False,
    "file_keychain": False,
    "environment_keychain": False,
    "ksec_use_keychain": False,
    "legacy_acl": False,
}
FORBIDDEN_FIELD_PARTS = (
    "credential", "secret", "ticket", "material", "native_handle", "nativehandle",
    "native_path", "nativepath", "raw_path",
)
SAFE_FIELD_NAMES = frozenset({"credential_manager"}) | frozenset(
    name.replace("-", "_") for name in DEPLOYMENT["mach_services"]
) | frozenset({"ticket_sha256"})


def tuple_digest(values: Mapping[str, object], fields: tuple[str, ...] = TUPLE_FIELDS) -> str:
    """Returns the canonical digest binding the exact shipped tuple."""
    payload = {field: values.get(field) for field in fields}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_row(row: object) -> list[str]:
    """Returns redacted structural errors for one independently-run macOS row."""
    if not isinstance(row, dict):
        return ["row is not an object"]
    if errors := shape_errors(row):
        return errors
    errors: list[str] = []
    if set(row) != ROW_FIELDS:
        errors.append("row fields are not exact")
    if row.get("platform") != "macos":
        errors.append("row platform is not macos")
    if row.get("architecture") != "arm64":
        errors.append("row architecture is not admitted")
    if not _macos_13_or_newer(row.get("os_version")):
        errors.append("row macOS version is not admitted")
    if row.get("disposition") != "verified":
        errors.append("row disposition is not verified")
    errors.extend(_tuple_errors(row.get("tuple")))
    errors.extend(deployment_errors(row.get("deployment"), row.get("tuple")))
    errors.extend(_signing_errors(row.get("signing")))
    errors.extend(code_identity_errors(row.get("code_identities"), row.get("tuple")))
    errors.extend(_runner_errors(row.get("runner")))
    errors.extend(_native_store_errors(row.get("native_store")))
    errors.extend(_artifact_scan_errors(row.get("artifact_scan")))
    errors.extend(_selector_errors(row.get("selectors"), row.get("runner")))
    errors.extend(_forbidden_field_errors(row))
    return errors


def validate_expected_tuples(value: object, rows: list[object]) -> list[str]:
    """Bind the sole Apple Silicon evidence row to its exact expected tuple."""
    if not isinstance(value, dict) or set(value) != ARCHITECTURES:
        return ["expected macOS tuples must contain exactly one arm64 tuple"]
    errors: list[str] = []
    for architecture in ARCHITECTURES:
        errors.extend(_tuple_errors(value[architecture]))
    for row in rows:
        if not isinstance(row, dict) or row.get("architecture") != "arm64":
            continue
        if row.get("tuple") != value[row["architecture"]]:
            errors.append(f"row tuple does not match expected {row['architecture']} tuple")
    return errors


def _tuple_errors(value: object) -> list[str]:
    if not isinstance(value, dict):
        return ["release tuple is missing"]
    if set(value) != {*TUPLE_FIELDS, "tuple_sha256"}:
        return ["release tuple fields are not exact"]
    if any(not _sha256(value.get(field)) for field in TUPLE_FIELDS):
        return ["release tuple digest is invalid"]
    for suffix in ("sha256", "code_identity_sha256"):
        if len({value[f"{role}_{suffix}"] for role in ("desktop", "writer", "daemon", "service")}) != 4:
            return ["release role identities must be distinct"]
    if value["deployment_sha256"] != canonical_digest(DEPLOYMENT):
        return ["release tuple deployment digest is not the admitted profile"]
    return [] if value.get("tuple_sha256") == tuple_digest(value) else ["release tuple binding mismatches"]


def _signing_errors(value: object) -> list[str]:
    if not isinstance(value, dict):
        return ["signing evidence is missing"]
    if set(value) != {
        "profile", "notarized", "ad_hoc", "team_id", "code_identifiers",
        "application_identifiers",
    }:
        return ["signing evidence fields are not exact"]
    if value.get("profile") != "developer_id" or value.get("notarized") is not True:
        return ["production signing or notarization is missing"]
    if value.get("ad_hoc") is not False:
        return ["ad-hoc signing is not accepted"]
    if value.get("team_id") != TEAM_ID:
        return ["signing team is not the admitted team"]
    if value.get("code_identifiers") != CODE_IDENTIFIERS:
        return ["code identifiers are not exact and distinct"]
    identities = value.get("application_identifiers")
    if identities != APPLICATION_IDENTIFIERS:
        return ["application identifiers are not exact"]
    return []


def _runner_errors(value: object) -> list[str]:
    if not isinstance(value, dict) or value.get("attestation_verified") is not True:
        return ["runner attestation is not verified"]
    if set(value) != {
        "workflow_run_id", "attestation_verified", "freshness_verified",
        "isolated_disposable_user", "icloud_data_present", "user_keychain_data_present",
    }:
        return ["runner evidence fields are not exact"]
    if not isinstance(value.get("workflow_run_id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value["workflow_run_id"]):
        return ["runner workflow identity is missing"]
    required = value.get("attestation_verified") is True and value.get("freshness_verified") is True and value.get("isolated_disposable_user") is True
    empty = value.get("icloud_data_present") is False and value.get("user_keychain_data_present") is False
    return [] if required and empty else ["runner is stale or not an isolated disposable user"]


def _native_store_errors(value: object) -> list[str]:
    if not isinstance(value, dict) or value != NATIVE_STORE or any(
        type(value[field]) is not type(expected)
        for field, expected in NATIVE_STORE.items()
    ):
        return ["native store is not the exact isolated DPK profile"]
    return []


def _artifact_scan_errors(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != {
        "files_scanned", "sensitive_value_matches", "scan_subject_sha256", "canary_sha256",
    }:
        return ["artifact scan fields are not exact"]
    if type(value.get("files_scanned")) is not int or not 0 < value["files_scanned"] <= 1000000:
        return ["artifact scan did not inspect files"]
    if not _sha256(value.get("scan_subject_sha256")) or value.get("canary_sha256") != CANARY_DIGEST:
        return ["artifact scan receipt digest is invalid"]
    return [] if _zero_count(value.get("sensitive_value_matches")) else ["artifact scan found sensitive values or invalid count"]


def _zero_count(value: object) -> bool:
    return type(value) is int and value == 0


def _selector_errors(value: object, runner: object) -> list[str]:
    workflow_run_id = runner.get("workflow_run_id") if isinstance(runner, dict) else None
    return selector_errors(value, REQUIRED_SELECTORS, workflow_run_id)


def _forbidden_field_errors(value: object, path: str = "") -> list[str]:
    if isinstance(value, dict):
        errors: list[str] = []
        for key, item in value.items():
            name = str(key).lower().replace("-", "_")
            if name not in SAFE_FIELD_NAMES and any(part in name for part in FORBIDDEN_FIELD_PARTS):
                errors.append(f"forbidden sensitive field at {path or 'row'}")
            safe = key if key in ROW_FIELDS | REQUIRED_SELECTORS else "redacted"
            errors.extend(_forbidden_field_errors(item, f"{path}.{safe}" if path else safe))
        return errors
    if isinstance(value, list):
        return [error for item in value for error in _forbidden_field_errors(item, path)]
    return []


def _sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _macos_13_or_newer(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"(1[3-9]|[2-9][0-9])(?:\.[0-9]{1,3}){0,2}", value) is not None
