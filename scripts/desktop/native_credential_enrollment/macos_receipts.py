"""Exact redacted receipt shapes shared with the protected macOS verifier."""
from __future__ import annotations

from collections.abc import Iterable
import re

from .macos_bindings import canonical_digest

TEAM_ID = "758F9Z45SR"
CANARY = "runne/native-qualification-export-canary/v1"
CANARY_DIGEST = canonical_digest({"needle": CANARY, "matches": 0})
ROLE_IDENTIFIERS = {
    "desktop": "com.runne.desktop",
    "writer": "runne",
    "daemon": "runned",
    "service": "com.runne.credential-service",
}
SELECTOR_FIELDS = {
    "status", "workflow_run_id", "case_receipt", "process_signal", "terminal_state",
    "namespace", "ticket_sha256", "process_signal_sha256", "terminal_state_sha256",
    "namespace_sha256",
}


def code_identity_errors(value: object, tuple_value: object) -> list[str]:
    if not isinstance(value, dict) or not isinstance(tuple_value, dict):
        return ["code identity receipts are invalid"]
    if set(value) != set(ROLE_IDENTIFIERS):
        return ["code identity receipts are incomplete"]
    for role, identifier in ROLE_IDENTIFIERS.items():
        observed = value.get(role)
        if not isinstance(observed, dict) or set(observed) != {"identifier", "teamIdentifier", "cdhash"}:
            return ["code identity receipts are not exact V3 identities"]
        if observed["identifier"] != identifier or observed["teamIdentifier"] != TEAM_ID:
            return ["code identity role or team differs"]
        if not isinstance(observed["cdhash"], str) or not re.fullmatch(r"[0-9a-f]{40}", observed["cdhash"]):
            return ["code identity cdhash is invalid"]
        if tuple_value.get(f"{role}_code_identity_sha256") != canonical_digest(observed):
            return ["code identity receipts differ from the release tuple"]
    return []


def selector_errors(value: object, selectors: Iterable[str], workflow_run_id: object) -> list[str]:
    expected_names = frozenset(selectors)
    if not isinstance(workflow_run_id, str) or not workflow_run_id:
        return ["runner workflow identity is invalid"]
    if not isinstance(value, dict) or set(value) != expected_names:
        return ["lifecycle selector set is incomplete"]
    for name, receipt in value.items():
        errors = _selector_errors(name, receipt, expected_names, workflow_run_id)
        if errors:
            return errors
    local, remote = value["local_verify_no_network"], value["remote_verify_after_local"]
    if local.get("status") != "verified" or type(local.get("network_attempts")) is not int or local["network_attempts"] != 0:
        return ["local verification receipt is invalid"]
    if remote.get("local_verification") != "verified" or type(remote.get("retry_count")) is not int or remote["retry_count"] != 0:
        return ["remote verification receipt is invalid"]
    return []


def _selector_errors(
    name: str, receipt: object, names: frozenset[str], workflow_run_id: str,
) -> list[str]:
    extras = {"network_attempts"} if name == "local_verify_no_network" else (
        {"local_verification", "retry_count"} if name == "remote_verify_after_local" else set()
    )
    allowed = SELECTOR_FIELDS | extras
    statuses = {"verified", "unsupported"} if name == "remote_verify_after_local" else {"verified"}
    if not isinstance(receipt, dict) or set(receipt) != allowed or receipt.get("status") not in statuses:
        return [f"selector {name} receipt fields are invalid"]
    run, status = receipt.get("workflow_run_id"), receipt["status"]
    if not isinstance(run, str) or run != workflow_run_id:
        return [f"selector {name} workflow identity is invalid"]
    ordinal = sorted(names).index(name)
    semantic = {
        "case_receipt": {"ordinal": ordinal, "selector": name, "workflow_run_id": run},
        "process_signal": {"outcome": status, "selector": name},
        "terminal_state": {"cleanup_verified": True, "selector": name, "state": status},
        "namespace": {"exact_cleanup": True, "selector": name},
    }
    digests = {
        "case_receipt": "ticket_sha256", "process_signal": "process_signal_sha256",
        "terminal_state": "terminal_state_sha256", "namespace": "namespace_sha256",
    }
    terminal, namespace = receipt["terminal_state"], receipt["namespace"]
    if not isinstance(terminal, dict) or not isinstance(namespace, dict):
        return [f"selector {name} semantic receipt is invalid"]
    if type(terminal.get("cleanup_verified")) is not bool or type(
        namespace.get("exact_cleanup")
    ) is not bool or any(
        not isinstance(receipt.get(field), dict)
        or canonical_digest(receipt[field]) != canonical_digest(item)
        or receipt.get(digests[field]) != canonical_digest(item)
        for field, item in semantic.items()
    ):
        return [f"selector {name} semantic receipt is invalid"]
    return []
