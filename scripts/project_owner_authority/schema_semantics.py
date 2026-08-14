"""Semantic closure shared by project-owner authority schema consumers."""

from __future__ import annotations

from datetime import datetime


def trust_config_errors(value: object) -> list[str]:
    """Reject trust-root relationships JSON Schema cannot express directly."""
    if not isinstance(value, dict):
        return ["trust config must be an object"]
    digests = value.get("schema_digests")
    if not isinstance(digests, list):
        return ["schema digests must be an array"]
    identifiers: list[object] = []
    for item in digests:
        if not isinstance(item, dict) or not isinstance(item.get("schema_id"), str):
            return ["schema digest must have an identifier"]
        identifiers.append(item["schema_id"])
    if any(left >= right for left, right in zip(identifiers, identifiers[1:])):
        return ["schema IDs must be strictly sorted and unique"]
    return []


def trust_v2_errors(value: object) -> list[str]:
    """Reject V2 shapes that do not bind the reviewed successor pin union."""
    if not isinstance(value, dict):
        return ["trust config must be an object"]
    expected = [
        "gocode.governance.v1-platform-scope-decision/1",
        "gocode.project-owner.authority-receipt/2",
        "gocode.project-owner.authority-receipt/3",
        "gocode.rc0.post-rc0-platform-composed-universe/1",
        "gocode.v1-platform-scope-claim-migration/1",
    ]
    pins = value.get("schema_digests")
    identifiers = [item.get("schema_id") for item in pins] if isinstance(pins, list) and all(isinstance(item, dict) for item in pins) else []
    if identifiers != expected:
        return ["schema pins must equal the reviewed V1 plus V3 union"]
    epoch = value.get("epoch")
    predecessor_schema = value.get("predecessor_schema_version")
    if epoch == 2 and predecessor_schema != "gocode.project-owner.trust-config/1":
        return ["epoch two must bind V1"]
    if isinstance(epoch, int) and epoch > 2 and predecessor_schema != "gocode.project-owner.trust-config/2":
        return ["later epochs must bind V2"]
    return []


def trust_v3_errors(value: object) -> list[str]:
    """Require the finalized immutable 17-schema promotion pin union."""
    if not isinstance(value, dict):
        return ["trust config must be an object"]
    if value.get("epoch") != 3:
        return ["V3 transition must advance to epoch three"]
    if value.get("predecessor_schema_version") != "gocode.project-owner.trust-config/2":
        return ["V3 must bind an exact V2 predecessor"]
    pins = value.get("schema_digests")
    expected = ["gocode.governance.v1-platform-scope-decision/1", "gocode.project-owner.authority-receipt/2", "gocode.project-owner.authority-receipt/3", "gocode.project-owner.authority-receipt/4", "gocode.rc0.post-rc0-platform-composed-universe/1", "gocode.release.post-rc0-stage-envelope/1", "gocode.release.promotion-state-snapshot/1", "gocode.release.publication-manifest/1", "gocode.release.rc1-qualification-decision/1", "gocode.release.rc2-signed-artifact-record/1", "gocode.release.rc2-signing-authorization/1", "gocode.release.rc2-threshold-update-metadata-set/1", "gocode.release.rc3-publication-authorization/1", "gocode.release.signed-envelope-inventory/1", "gocode.release.signed-envelope-verification-report/1", "gocode.release.unsigned-candidate-manifest/1", "gocode.v1-platform-scope-claim-migration/1"]
    actual = [item.get("schema_id") for item in pins] if isinstance(pins, list) and all(isinstance(item, dict) for item in pins) else []
    return [] if actual == expected else ["V3 schema pins must equal the finalized union"]


def reconciliation_receipt_errors(value: object) -> list[str]:
    """Validate reconciliation constraints JSON Schema cannot express directly."""
    if not isinstance(value, dict):
        return ["reconciliation receipt must be an object"]
    issued_at = value.get("issued_at")
    try:
        datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return ["issued_at must be a real UTC instant"]
    return []


def promotion_bootstrap_errors(value: object) -> list[str]:
    """Reject V4 delegation reuse and impossible windows beyond JSON Schema."""
    if not isinstance(value, dict):
        return ["promotion bootstrap must be an object"]
    delegations = value.get("delegations")
    if not isinstance(delegations, list) or len(delegations) != 3:
        return ["exactly three delegations are required"]
    fields = ("principal_id", "controlling_account_id", "lane_id", "key_id", "public_key")
    for field in fields:
        values = [item.get(field) for item in delegations if isinstance(item, dict)]
        if len(values) != 3 or len(set(values)) != 3:
            return [f"delegation {field} values must be distinct"]
    issued_at, not_before, expires_at = value.get("issued_at"), value.get("not_before"), value.get("expires_at")
    if not all(isinstance(item, str) for item in (issued_at, not_before, expires_at)) or not issued_at < not_before < expires_at:
        return ["bootstrap timestamps must be strictly ordered"]
    subject = value.get("subject")
    documents = value.get("documents")
    if not isinstance(subject, dict) or not isinstance(documents, list):
        return ["subject and documents are required"]
    width = {"sha1": 40, "sha256": 64}.get(subject.get("object_format"))
    if width is None or any(not isinstance(subject.get(name), str) or len(subject[name]) != width for name in ("commit_oid", "tree_oid")):
        return ["subject OIDs must match object format"]
    if any(not isinstance(item, dict) or not isinstance(item.get("blob_oid"), str) or len(item["blob_oid"]) != width for item in documents):
        return ["document OIDs must match subject object format"]
    return []


def stage_envelope_errors(value: object) -> list[str]:
    """Reject the self-referential enclosing envelope digest from a payload."""
    if not isinstance(value, dict) or not isinstance(value.get("payload"), dict):
        return ["stage payload must be an object"]
    def has_enclosing_hash(item: object) -> bool:
        if isinstance(item, dict):
            return any(key in {"envelope_sha256", "stage_envelope_sha256"} or has_enclosing_hash(child) for key, child in item.items())
        return any(has_enclosing_hash(child) for child in item) if isinstance(item, list) else False
    return ["payload cannot bind enclosing envelope"] if has_enclosing_hash(value["payload"]) else []
