"""MacOS-only structural checks for credential enrollment evidence.

This module validates redacted receipts only. It cannot qualify a package or
turn on a runtime capability; that decision remains with protected CI and the
signed package admission boundary.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

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
})
BASE_TUPLE_FIELDS = (
    "desktop_sha256", "writer_sha256", "daemon_sha256", "contract_sha256",
    "candidate_sha256",
)
TUPLE_FIELDS = (
    "desktop_sha256", "writer_sha256", "daemon_sha256", "service_sha256",
    "launch_agent_plist_sha256", "entitlements_sha256", "provisioning_sha256",
    "protocol_sha256", "contract_sha256", "candidate_sha256",
)
ROW_FIELDS = {
    "platform", "architecture", "os_version", "disposition", "tuple", "signing",
    "runner", "native_store", "artifact_scan", "selectors",
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
SAFE_FIELD_NAMES = frozenset({"credential_manager"})


def tuple_digest(values: Mapping[str, object], fields: tuple[str, ...] = TUPLE_FIELDS) -> str:
    """Returns the canonical digest binding the exact shipped tuple."""
    payload = {field: values.get(field) for field in fields}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_row(row: object) -> list[str]:
    """Returns redacted structural errors for one independently-run macOS row."""
    if not isinstance(row, dict):
        return ["row is not an object"]
    errors: list[str] = []
    if set(row) != ROW_FIELDS:
        errors.append("row fields are not exact")
    if row.get("platform") != "macos":
        errors.append("row platform is not macos")
    if row.get("architecture") not in ARCHITECTURES:
        errors.append("row architecture is not admitted")
    if not _macos_13_or_newer(row.get("os_version")):
        errors.append("row macOS version is not admitted")
    if row.get("disposition") != "verified":
        errors.append("row disposition is not verified")
    errors.extend(_tuple_errors(row.get("tuple")))
    errors.extend(_signing_errors(row.get("signing")))
    errors.extend(_runner_errors(row.get("runner")))
    errors.extend(_native_store_errors(row.get("native_store")))
    errors.extend(_artifact_scan_errors(row.get("artifact_scan")))
    errors.extend(_selector_errors(row.get("selectors")))
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
        if not isinstance(row, dict) or row.get("architecture") not in ARCHITECTURES:
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
    if not isinstance(value.get("workflow_run_id"), str) or not value["workflow_run_id"]:
        return ["runner workflow identity is missing"]
    required = value.get("freshness_verified") is True and value.get("isolated_disposable_user") is True
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
    if not isinstance(value, dict) or set(value) != {"files_scanned", "sensitive_value_matches"}:
        return ["artifact scan fields are not exact"]
    if type(value.get("files_scanned")) is not int or value["files_scanned"] <= 0:
        return ["artifact scan did not inspect files"]
    return [] if _zero_count(value.get("sensitive_value_matches")) else ["artifact scan found sensitive values or invalid count"]


def _zero_count(value: object) -> bool:
    return type(value) is int and value == 0


def _selector_errors(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != REQUIRED_SELECTORS:
        return ["lifecycle selector set is incomplete"]
    for name, receipt in value.items():
        expected_statuses = {"verified", "unsupported"} if name == "remote_verify_after_local" else {"verified"}
        if not isinstance(receipt, dict) or receipt.get("status") not in expected_statuses:
            return [f"selector {name} has an invalid status"]
        allowed = {"status", "network_attempts"} if name == "local_verify_no_network" else {
            "status", "local_verification", "retry_count"
        } if name == "remote_verify_after_local" else {"status"}
        if set(receipt) != allowed:
            return [f"selector {name} fields are not exact"]
    local, remote = value["local_verify_no_network"], value["remote_verify_after_local"]
    if local.get("status") != "verified" or not _zero_count(local.get("network_attempts")):
        return ["local verification must be verified without network"]
    if remote.get("local_verification") != "verified" or not _zero_count(remote.get("retry_count")):
        return ["remote verification lacks current local success or has retries"]
    return []


def _forbidden_field_errors(value: object, path: str = "") -> list[str]:
    if isinstance(value, dict):
        errors: list[str] = []
        for key, item in value.items():
            name = str(key).lower().replace("-", "_")
            if name not in SAFE_FIELD_NAMES and any(part in name for part in FORBIDDEN_FIELD_PARTS):
                errors.append(f"forbidden sensitive field at {path or 'row'}")
            errors.extend(_forbidden_field_errors(item, f"{path}.{key}" if path else str(key)))
        return errors
    if isinstance(value, list):
        return [error for item in value for error in _forbidden_field_errors(item, path)]
    return []


def _sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _macos_13_or_newer(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return int(value.split(".", 1)[0]) >= 13
    except ValueError:
        return False
