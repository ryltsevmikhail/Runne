"""Exact ADR-0031 public deployment metadata; no native inspection or paths."""
import hashlib
import json

TEAM_ID = "758F9Z45SR"
SERVICE_ID = "com.runne.credential-service"
SERVICE_GROUP = f"{TEAM_ID}.{SERVICE_ID}"
DEPLOYMENT = {
    "release_tuple_version": 3,
    "helper_bundle_identifier": SERVICE_ID,
    "helper_executable": "runne-credential-service",
    "launch_agent_label": SERVICE_ID,
    "bundle_program": "Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service",
    "keep_alive": False,
    "run_at_load": False,
    "mach_services": {
        f"{SERVICE_ID}.desktop.v1": True,
        f"{SERVICE_ID}.runtime.v1": True,
        f"{SERVICE_ID}.writer.v1": True,
    },
    "entitlements": {
        "desktop": {
            "com.apple.application-identifier": f"{TEAM_ID}.com.runne.desktop",
            "com.apple.developer.team-identifier": TEAM_ID,
            "keychain-access-groups": [f"{TEAM_ID}.com.runne.desktop"],
        },
        "writer": {},
        "daemon": {},
        "service": {
            "com.apple.application-identifier": SERVICE_GROUP,
            "com.apple.developer.team-identifier": TEAM_ID,
            "keychain-access-groups": [SERVICE_GROUP],
        },
    },
    "transport": "nsxpc_role_listeners",
    "magic": "RNCRED01",
    "registration_version": 1,
    "provider_frame_version": 2,
    "runtime_envelope_version": 2,
    "runtime_mac_version": 3,
    "provisioning": "distribution_verified",
    "package": "immutable_installed",
}
ADDITIONAL_SELECTORS = frozenset({
    "same_uid_native_find_denied", "same_uid_native_read_denied",
    "same_uid_native_update_denied", "same_uid_native_delete_denied",
    "wrong_desktop_endpoint_peer_denied", "wrong_runtime_endpoint_peer_denied",
    "wrong_writer_endpoint_peer_denied", "wrong_service_peer_denied",
    "kill_desktop_process", "kill_writer_process", "kill_runtime_process",
    "kill_service_launchd_restart", "kill_registration_ack_loss",
    "duplicate_request_denied", "runtime_restart_old_session_denied",
    "terminal_exact_namespace_cleanup",
})


def canonical_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("ascii")).hexdigest()


def deployment_errors(value: object, tuple_value: object) -> list[str]:
    if not isinstance(value, dict) or canonical_digest(value) != canonical_digest(DEPLOYMENT):
        return ["deployment metadata is not the exact ADR-0031 profile"]
    if not isinstance(tuple_value, dict) or tuple_value.get("deployment_sha256") != canonical_digest(value):
        return ["deployment metadata is not bound to the expected release tuple"]
    return []
