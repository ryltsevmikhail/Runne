"""Immutable, redacted macOS DPK evidence contract for the external verifier."""
from __future__ import annotations

import hashlib
import json
import re

TEAM = "758F9Z45SR"
SERVICE = "com.runne.credential-service"
DEPLOYMENT = {"release_tuple_version":3,"helper_bundle_identifier":SERVICE,"helper_executable":"runne-credential-service","launch_agent_label":SERVICE,"bundle_program":"Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service","keep_alive":False,"run_at_load":False,"mach_services":{f"{SERVICE}.desktop.v1":True,f"{SERVICE}.runtime.v1":True,f"{SERVICE}.writer.v1":True},"entitlements":{"desktop":{"com.apple.application-identifier":f"{TEAM}.com.runne.desktop","com.apple.developer.team-identifier":TEAM,"keychain-access-groups":[f"{TEAM}.com.runne.desktop"]},"writer":{},"daemon":{},"service":{"com.apple.application-identifier":f"{TEAM}.{SERVICE}","com.apple.developer.team-identifier":TEAM,"keychain-access-groups":[f"{TEAM}.{SERVICE}"]}},"transport":"nsxpc_role_listeners","magic":"RNCRED01","registration_version":1,"provider_frame_version":2,"runtime_envelope_version":2,"runtime_mac_version":3,"provisioning":"distribution_verified","package":"immutable_installed"}
TUPLE = ("desktop_sha256","writer_sha256","daemon_sha256","service_sha256","launch_agent_plist_sha256","entitlements_sha256","provisioning_sha256","protocol_sha256","contract_sha256","candidate_sha256","release_tuple_v3_sha256","deployment_sha256","desktop_code_identity_sha256","writer_code_identity_sha256","daemon_code_identity_sha256","service_code_identity_sha256")
SELECTORS = frozenset({"clean_install","n_to_n_plus_1","rollback","mixed_child_manifest_denied","symlink_denied","hardlink_denied","pid_reuse_denied","package_skew_denied","post_spawn_executable_image_skew_denied","post_spawn_codesign_skew_denied","unsigned_package_denied","ad_hoc_signature_denied","keychain_executable_acl_denied","third_process_broker_denied","pair_create_readback","rotation","revoke_fence_delete","crash_recovery","replay_denied","local_verify_no_network","remote_verify_after_local","standalone_writer_denied","standalone_daemon_denied","wrong_peer_denied","kill_before_service_consume","kill_after_service_consume","kill_before_native_effect","kill_after_native_effect","kill_before_readback","kill_after_readback","kill_before_reply","kill_after_reply","kill_before_lifecycle_cas","kill_after_lifecycle_cas","stored_attributes_verified","service_restart_persistence","duplicate_version_denied","account_only_mismatch_denied","same_uid_native_find_denied","same_uid_native_read_denied","same_uid_native_update_denied","same_uid_native_delete_denied","wrong_desktop_endpoint_peer_denied","wrong_runtime_endpoint_peer_denied","wrong_writer_endpoint_peer_denied","wrong_service_peer_denied","kill_desktop_process","kill_writer_process","kill_runtime_process","kill_service_launchd_restart","kill_registration_ack_loss","duplicate_request_denied","runtime_restart_old_session_denied","terminal_exact_namespace_cleanup"})
ROW = frozenset({"platform","architecture","os_version","disposition","tuple","signing","code_identities","runner","native_store","artifact_scan","selectors","deployment"})
STORE = {"access_group":f"{TEAM}.{SERVICE}","data_protection_keychain":True,"accessibility":"when_unlocked_this_device_only","synchronizable":False,"file_keychain":False,"environment_keychain":False,"ksec_use_keychain":False,"legacy_acl":False}
ROLE_PATHS = {"desktop":"Contents/MacOS/runne-desktop",
              "writer":"Contents/MacOS/runne",
              "daemon":"Contents/MacOS/runned",
              "service":"Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service"}
CANARY = "runne/native-qualification-export-canary/v1"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def tuple_digest(value: dict[str, object]) -> str:
    return digest({name: value.get(name) for name in TUPLE})


def validate_row(row: object, tuples: object, policy: dict[str, object]) -> None:
    if not isinstance(row, dict) or set(row) != ROW:
        _reject("row fields are not exact")
    if row.get("platform") != "macos" or row.get("architecture") != "arm64" or not _macos(row.get("os_version")) or row.get("disposition") != "verified":
        _reject("row platform is invalid")
    if not isinstance(tuples, dict) or set(tuples) != {"arm64"} or row.get("tuple") != tuples.get("arm64"):
        _reject("expected tuple is invalid")
    _tuple(row["tuple"], policy)
    _deployment(row.get("deployment"))
    _signing(row.get("signing")); _code_identities(row.get("code_identities"), row["tuple"])
    _runner(row.get("runner")); _store(row.get("native_store"))
    _scan(row.get("artifact_scan")); _selectors(row.get("selectors"), row["runner"]["workflow_run_id"]); _forbidden(row)


def _tuple(value: object, policy: dict[str, object]) -> None:
    if not isinstance(value, dict) or set(value) != {*TUPLE, "tuple_sha256"} or any(not sha(value.get(name)) for name in TUPLE):
        _reject("tuple is invalid")
    if value.get("tuple_sha256") != tuple_digest(value) or value.get("deployment_sha256") != digest(DEPLOYMENT):
        _reject("tuple binding is invalid")
    if value.get("candidate_sha256") != policy["candidate_sha256"] or value.get("release_tuple_v3_sha256") != policy["release_tuple_v3_sha256"]:
        _reject("tuple differs from protected policy")
    for suffix in ("sha256", "code_identity_sha256"):
        if len({value[f"{role}_{suffix}"] for role in ("desktop", "writer", "daemon", "service")}) != 4:
            _reject("tuple role identities are not distinct")


def _signing(value: object) -> None:
    expected = {"profile","notarized","ad_hoc","team_id","code_identifiers","application_identifiers"}
    code = {"desktop":"com.runne.desktop","writer":"runne","daemon":"runned","service":SERVICE}
    app = {"desktop":f"{TEAM}.com.runne.desktop","service":f"{TEAM}.{SERVICE}"}
    if not isinstance(value, dict) or set(value) != expected or value.get("profile") != "developer_id" or value.get("notarized") is not True or value.get("ad_hoc") is not False or value.get("team_id") != TEAM or value.get("code_identifiers") != code or value.get("application_identifiers") != app:
        _reject("signing evidence is invalid")


def _deployment(value: object) -> None:
    if not isinstance(value, dict) or canonical(value) != canonical(DEPLOYMENT):
        _reject("deployment is invalid")


def _code_identities(value: object, tuple_value: dict[str, object]) -> None:
    identifiers = {"desktop":"com.runne.desktop", "writer":"runne", "daemon":"runned", "service":SERVICE}
    fields = {"identifier", "teamIdentifier", "cdhash"}
    if not isinstance(value, dict) or set(value) != set(identifiers): _reject("code identities are incomplete")
    for role, identifier in identifiers.items():
        observed = value.get(role)
        if not isinstance(observed, dict) or set(observed) != fields or observed.get("identifier") != identifier or observed.get("teamIdentifier") != TEAM or not isinstance(observed.get("cdhash"), str) or re.fullmatch(r"[0-9a-f]{40}", observed["cdhash"]) is None or tuple_value[f"{role}_code_identity_sha256"] != digest(observed):
            _reject("code identity differs from qualified tuple")


def _runner(value: object) -> None:
    fields = {"workflow_run_id","attestation_verified","freshness_verified","isolated_disposable_user","icloud_data_present","user_keychain_data_present"}
    if not isinstance(value, dict) or set(value) != fields or not isinstance(value.get("workflow_run_id"), str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value["workflow_run_id"]) is None:
        _reject("runner evidence is invalid")
    if value.get("attestation_verified") is not True or value.get("freshness_verified") is not True or value.get("isolated_disposable_user") is not True or value.get("icloud_data_present") is not False or value.get("user_keychain_data_present") is not False:
        _reject("runner is not isolated")


def _store(value: object) -> None:
    if not isinstance(value, dict) or value != STORE or any(type(value[key]) is not type(expected) for key, expected in STORE.items()):
        _reject("native store is invalid")


def _scan(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {"files_scanned","sensitive_value_matches","scan_subject_sha256","canary_sha256"} or type(value.get("files_scanned")) is not int or not 0 < value["files_scanned"] <= 1000000 or type(value.get("sensitive_value_matches")) is not int or value["sensitive_value_matches"] != 0 or not sha(value.get("scan_subject_sha256")) or value.get("canary_sha256") != digest({"needle":CANARY,"matches":0}):
        _reject("artifact scan is invalid")


def _selectors(value: object, run: str) -> None:
    if not isinstance(value, dict) or set(value) != SELECTORS:
        _reject("selector set is incomplete")
    for name, receipt in value.items():
        required = {"status","workflow_run_id","case_receipt","process_signal","terminal_state","namespace","ticket_sha256","process_signal_sha256","terminal_state_sha256","namespace_sha256"}
        allowed = required | ({"network_attempts"} if name == "local_verify_no_network" else {"local_verification","retry_count"} if name == "remote_verify_after_local" else set())
        states = {"verified","unsupported"} if name == "remote_verify_after_local" else {"verified"}
        hashes = {"ticket_sha256","process_signal_sha256","terminal_state_sha256","namespace_sha256"}
        if not isinstance(receipt, dict) or set(receipt) != allowed or receipt.get("status") not in states or receipt.get("workflow_run_id") != run or any(not sha(receipt.get(field)) for field in hashes):
            _reject("selector receipt is invalid")
        ordinal = sorted(SELECTORS).index(name)
        semantic = {
            "case_receipt": {"ordinal":ordinal,"selector":name,"workflow_run_id":run},
            "process_signal": {"outcome":receipt["status"],"selector":name},
            "terminal_state": {"cleanup_verified":True,"selector":name,"state":receipt["status"]},
            "namespace": {"exact_cleanup":True,"selector":name},
        }
        digests = {"case_receipt":"ticket_sha256","process_signal":"process_signal_sha256",
                   "terminal_state":"terminal_state_sha256","namespace":"namespace_sha256"}
        if any(not isinstance(receipt[field], dict) or canonical(receipt[field]) != canonical(item)
               or receipt[digests[field]] != digest(item) for field, item in semantic.items()):
            _reject("selector semantic receipt is invalid")
    if value["local_verify_no_network"].get("status") != "verified" or value["local_verify_no_network"].get("network_attempts") != 0 or type(value["local_verify_no_network"]["network_attempts"]) is not int:
        _reject("local verification receipt is invalid")
    remote = value["remote_verify_after_local"]
    if remote.get("local_verification") != "verified" or type(remote.get("retry_count")) is not int or remote["retry_count"] != 0:
        _reject("remote verification receipt is invalid")


def _forbidden(value: object, name: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower().replace("-", "_")
            if key not in {"credential_manager", "ticket_sha256", *DEPLOYMENT["mach_services"]} and any(word in lowered for word in ("credential","secret","ticket","material","native_handle","native_path","raw_path")):
                _reject("forbidden evidence field")
            _forbidden(item, str(key))
    elif isinstance(value, list):
        for item in value: _forbidden(item, name)


def _macos(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"(1[3-9]|[2-9][0-9])(?:\.[0-9]{1,3}){0,2}", value) is not None


def _reject(reason: str) -> None:
    from codec import Rejected
    raise Rejected(reason)
