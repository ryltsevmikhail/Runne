"""Structural closure for two artifact measurements and native host evidence."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.external_envelope import PrincipalBinding, VerifiedEnvelope, require_fixture_verified
from scripts.rc0_policy.rules import BINDING_FIELDS, validate_content_locator, validate_portable_relative_path


_MEASUREMENT_SCHEMA = "gocode.rc0.artifact-measurement-record/1"
_HOST_SCHEMA = "gocode.rc0.native-host-evidence-record/1"
_PROFILES = frozenset((
    "gocode.rc0.evidence-profile/3", "gocode.rc0.evidence-profile/4",
))
_HEX = re.compile(r"[0-9a-f]{64}")
_MEASUREMENT_FIELDS = frozenset((
    "schema_version", "repository_id", "mapping_policy_envelope_sha256",
    "adjunct_trust_registry_envelope_sha256", "adjunct_trust_registry_payload_sha256",
    "rc0_qualification_policy_digest", "active_activation_snapshot_envelope_sha256",
    "common_binding_group", "common_binding_group_payload_sha256", "platform_scope_id",
    "artifact_slot_id", "artifact_kind", "relative_path", "artifact_sha256", "size", "locator",
    "artifact_manifest_payload", "artifact_manifest_payload_sha256",
    "product_manifest_payload_sha256", "classifier_implementation_sha256",
    "classifier_dependency_set_sha256", "classifier_lane_id", "classifier_run_id",
    "observed_at", "freshness_deadline",
))
_HOST_FIELDS = frozenset((
    "schema_version", "repository_id", "mapping_policy_envelope_sha256",
    "adjunct_trust_registry_envelope_sha256", "adjunct_trust_registry_payload_sha256",
    "rc0_qualification_policy_digest", "active_activation_snapshot_envelope_sha256",
    "common_binding_group", "common_binding_group_payload_sha256", "platform_scope_id",
    "os_family", "os_version", "os_build", "kernel_or_image_sha256", "architecture", "native_mode",
    "backend_id", "backend_version", "probe_set_payload_sha256",
    "enforcement_descriptor_payload_sha256", "workflow_run_id", "executed_artifacts",
    "control_results", "observed_at", "freshness_deadline",
))
_RAW_FIELDS = frozenset(("relative_path", "sha256", "size", "locator"))
_EXECUTED_FIELDS = frozenset((
    "artifact_slot_id", "artifact_kind", "relative_path", "sha256", "size", "locator",
    "artifact_manifest_payload_sha256", "product_manifest_payload_sha256",
))
_MANIFEST_FIELDS = frozenset(("schema_version", "artifact_slot_id", "artifact_kind", "raw_artifact", "entries", "shape_results"))
_ENTRY_FIELDS = frozenset((
    "relative_path", "sha256", "size", "mode", "executable_architecture",
    "entitlement_capability_descriptor_sha256", "role",
))
_SHAPE_FIELDS = frozenset((
    "path_normalization", "traversal", "symlink", "hardlink", "special_file", "case_collision",
    "unlisted_package_script", "linux_product_payload", "windows_helper", "macos_app_dmg",
))
_COMMON_FIELDS = frozenset(BINDING_FIELDS)
_INVENTORIES = {
    "linux-ubuntu-24_04-x86_64-production": (("linux-appimage", "appimage"), ("linux-deb", "deb")),
    "windows-11-24h2-x86_64-production": (("windows-installer-unsigned", "msi"),),
    "macos-14-arm64-development-preview": (("macos-app-development-adhoc", "macos_app_bundle"), ("macos-dmg-development-adhoc", "dmg")),
}


class ArtifactClosureFailure(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ArtifactClosure:
    artifact_slot_id: str
    artifact_kind: str
    relative_path: str
    artifact_sha256: str
    size: int
    locator: str
    artifact_manifest_payload_sha256: str
    product_manifest_payload_sha256: str
    classifier_identities: tuple[PrincipalBinding, PrincipalBinding]
    classifier_implementation_sha256s: tuple[str, str]
    classifier_dependency_set_sha256s: tuple[str, str]
    classifier_run_ids: tuple[str, str]


def _fail(code: str) -> None:
    raise ArtifactClosureFailure(code)


def _text(value: object) -> bool:
    return type(value) is str and bool(value)


def _digest(value: object) -> bool:
    return type(value) is str and _HEX.fullmatch(value) is not None


def _signer(value: VerifiedEnvelope) -> PrincipalBinding:
    direct = (
        value.issuer_role, value.issuer_subject_id, value.issuer_controlling_account_id,
        value.issuer_delegated_session_id, value.issuer_lane_id,
    )
    principal = value.trust.principal
    if type(principal) is not PrincipalBinding or any(not _text(item) for item in direct) or any(not _text(item) for item in (principal.role_id, principal.subject_id, principal.controlling_account_id, principal.delegated_session_id, principal.lane_id)):
        _fail("FIXTURE_ENVELOPE_INVALID")
    if direct != (principal.role_id, principal.subject_id, principal.controlling_account_id, principal.delegated_session_id, principal.lane_id):
        _fail("FIXTURE_ENVELOPE_INVALID")
    return PrincipalBinding(*direct)


def _record(value: VerifiedEnvelope, schema: str, role: str, fields: frozenset[str]) -> dict[str, object]:
    try:
        require_fixture_verified(value)
        payload = loads_canonical(value.payload_canonical_bytes)
    except Exception as error:
        raise ArtifactClosureFailure("FIXTURE_ENVELOPE_INVALID") from error
    if type(payload) is not dict or canonical_bytes(payload) != value.payload_canonical_bytes or type(value.payload_schema_id) is not str:
        _fail("FIXTURE_ENVELOPE_INVALID")
    signer = _signer(value)
    if value.payload_schema_id != schema or signer.role_id != role or set(payload) != fields:
        _fail("RECORD_SCHEMA_MISMATCH")
    return payload


def _raw(value: dict[str, object], sha_name: str) -> tuple[str, str, int, str]:
    path, digest, size, locator = value.get("relative_path"), value.get(sha_name), value.get("size"), value.get("locator")
    if not _text(path) or not _digest(digest) or type(size) is not int or isinstance(size, bool) or size < 0 or not _text(locator):
        _fail("ARTIFACT_RECORD_INVALID")
    return path, digest, size, locator


def _lineage(value: dict[str, object]) -> tuple[object, ...]:
    common = value.get("common_binding_group")
    if type(common) is not dict or set(common) != _COMMON_FIELDS or common.get("repository_id") != "gocode" or type(common.get("evidence_attempt_id")) is not str or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", common["evidence_attempt_id"]) is None or not _digest(common.get("policy_digest")) or not _digest(common.get("evidence_bundle_digest")) or common.get("profile") not in _PROFILES or type(common.get("policy_revision")) is not int or isinstance(common["policy_revision"], bool) or common["policy_revision"] < 1 or any(type(common.get(name)) is not str or re.fullmatch(r"[0-9a-f]{40}", common[name]) is None for name in ("candidate_source_sha", "observed_evidence_revision")):
        _fail("LINEAGE_INVALID")
    artifacts = common.get("exact_artifact_bindings")
    if type(artifacts) is not list or not artifacts or len(artifacts) > 4096 or len({canonical_bytes(item) for item in artifacts if type(item) is dict}) != len(artifacts):
        _fail("LINEAGE_INVALID")
    for item in artifacts:
        if type(item) is not dict or set(item) != _RAW_FIELDS or validate_portable_relative_path(item.get("relative_path")) or not _digest(item.get("sha256")) or type(item.get("size")) is not int or isinstance(item["size"], bool) or not 0 <= item["size"] <= 2**64 - 1 or validate_content_locator(item.get("locator")) or (item["locator"].startswith("cas:sha256:") and item["locator"].removeprefix("cas:sha256:") != item["sha256"]):
            _fail("LINEAGE_INVALID")
    common_bytes = canonical_bytes(common)
    names = (
        "mapping_policy_envelope_sha256", "adjunct_trust_registry_envelope_sha256",
        "adjunct_trust_registry_payload_sha256", "rc0_qualification_policy_digest",
        "active_activation_snapshot_envelope_sha256", "common_binding_group_payload_sha256",
    )
    if type(value.get("repository_id")) is not str or value["repository_id"] != "gocode" or not _text(value.get("platform_scope_id")) or any(not _digest(value.get(name)) for name in names) or common["policy_digest"] != value["rc0_qualification_policy_digest"] or hashlib.sha256(common_bytes).hexdigest() != value["common_binding_group_payload_sha256"]:
        _fail("LINEAGE_INVALID")
    return (value["repository_id"], *(value[name] for name in names[:5]), common_bytes, value["common_binding_group_payload_sha256"], value["platform_scope_id"])


def _manifest(value: object, slot: str, kind: str, raw: tuple[str, str, int, str]) -> bytes:
    if type(value) is not dict or set(value) != _MANIFEST_FIELDS:
        _fail("ARTIFACT_MANIFEST_INVALID")
    if value.get("schema_version") != "gocode.rc0.artifact-manifest-payload/1" or value.get("artifact_slot_id") != slot or value.get("artifact_kind") != kind:
        _fail("ARTIFACT_MANIFEST_INVALID")
    nested = value.get("raw_artifact")
    if type(nested) is not dict or set(nested) != _RAW_FIELDS or _raw(nested, "sha256") != raw:
        _fail("ARTIFACT_MANIFEST_INVALID")
    entries, shapes = value.get("entries"), value.get("shape_results")
    if type(entries) is not list or not entries or type(shapes) is not dict or set(shapes) != _SHAPE_FIELDS:
        _fail("ARTIFACT_MANIFEST_INVALID")
    encoded: list[bytes] = []
    for entry in entries:
        if type(entry) is not dict or set(entry) != _ENTRY_FIELDS or not _text(entry.get("relative_path")) or not _digest(entry.get("sha256")) or type(entry.get("size")) is not int or isinstance(entry["size"], bool) or entry["size"] < 0 or any(not _text(entry.get(name)) for name in ("mode", "executable_architecture", "role")) or not _digest(entry.get("entitlement_capability_descriptor_sha256")):
            _fail("ARTIFACT_MANIFEST_INVALID")
        encoded.append(canonical_bytes(entry))
    if encoded != sorted(encoded) or len(set(encoded)) != len(encoded) or len({entry["relative_path"] for entry in entries}) != len(entries) or any(result not in {"PASS", "FAILED", "NOT_APPLICABLE"} for result in shapes.values()):
        _fail("ARTIFACT_MANIFEST_INVALID")
    return canonical_bytes(value)


def _measurement(value: VerifiedEnvelope, role: str) -> tuple[dict[str, object], tuple[str, str, int, str], bytes, PrincipalBinding]:
    payload = _record(value, _MEASUREMENT_SCHEMA, role, _MEASUREMENT_FIELDS)
    raw = _raw(payload, "artifact_sha256")
    slot, kind = payload.get("artifact_slot_id"), payload.get("artifact_kind")
    if not _text(slot) or not _text(kind) or not _text(payload.get("platform_scope_id")) or any(not _digest(payload.get(name)) for name in ("artifact_manifest_payload_sha256", "product_manifest_payload_sha256", "classifier_implementation_sha256", "classifier_dependency_set_sha256")) or not _text(payload.get("classifier_lane_id")) or not _text(payload.get("classifier_run_id")):
        _fail("ARTIFACT_RECORD_INVALID")
    if payload["classifier_lane_id"] != value.issuer_lane_id:
        _fail("CLASSIFIER_DIVERSITY_MISMATCH")
    manifest = _manifest(payload["artifact_manifest_payload"], slot, kind, raw)
    if hashlib.sha256(manifest).hexdigest() != payload["artifact_manifest_payload_sha256"]:
        _fail("CLASSIFIER_MANIFEST_MISMATCH")
    principal = _signer(value)
    return payload, raw, manifest, principal


def _same_measurement(first: dict[str, object], second: dict[str, object], raw: tuple[str, str, int, str], manifest_a: bytes, manifest_b: bytes) -> None:
    if any(first[name] != second[name] for name in ("platform_scope_id", "artifact_slot_id", "artifact_kind")) or raw != _raw(second, "artifact_sha256"):
        _fail("ARTIFACT_TUPLE_MISMATCH")
    if manifest_a != manifest_b or any(first[name] != second[name] for name in ("artifact_manifest_payload_sha256", "product_manifest_payload_sha256")):
        _fail("CLASSIFIER_MANIFEST_MISMATCH")


def _diverse(first: dict[str, object], second: dict[str, object], a: PrincipalBinding, b: PrincipalBinding) -> None:
    identities = (a.subject_id, a.controlling_account_id, a.delegated_session_id, a.lane_id, b.subject_id, b.controlling_account_id, b.delegated_session_id, b.lane_id)
    if any(not _text(item) for item in identities) or len(set(identities)) != len(identities) or any(first[name] == second[name] for name in ("classifier_implementation_sha256", "classifier_dependency_set_sha256", "classifier_lane_id", "classifier_run_id")):
        _fail("CLASSIFIER_DIVERSITY_MISMATCH")


def _host(payload: dict[str, object], measurement: dict[str, object], raw: tuple[str, str, int, str]) -> None:
    rows = payload.get("executed_artifacts")
    inventory = _INVENTORIES.get(measurement["platform_scope_id"])
    if payload.get("platform_scope_id") != measurement["platform_scope_id"] or inventory is None or type(rows) is not list or len(rows) != len(inventory):
        _fail("HOST_ARTIFACT_MISMATCH")
    matches = 0
    tuples: set[tuple[str, str, int, str]] = set()
    actual_inventory: list[tuple[str, str]] = []
    for row in rows:
        if type(row) is not dict or set(row) != _EXECUTED_FIELDS or not _text(row.get("artifact_slot_id")) or not _text(row.get("artifact_kind")) or any(not _digest(row.get(name)) for name in ("artifact_manifest_payload_sha256", "product_manifest_payload_sha256")):
            _fail("HOST_ARTIFACT_MISMATCH")
        actual_inventory.append((row["artifact_slot_id"], row["artifact_kind"]))
        host_raw = _raw(row, "sha256")
        if host_raw in tuples:
            _fail("HOST_ARTIFACT_MISMATCH")
        tuples.add(host_raw)
        expected = (measurement["artifact_slot_id"], measurement["artifact_kind"], *raw, measurement["artifact_manifest_payload_sha256"], measurement["product_manifest_payload_sha256"])
        actual = (row["artifact_slot_id"], row["artifact_kind"], *host_raw, row["artifact_manifest_payload_sha256"], row["product_manifest_payload_sha256"])
        if actual == expected:
            matches += 1
    if tuple(actual_inventory) != inventory or len({slot for slot, _ in actual_inventory}) != len(actual_inventory) or matches != 1:
        _fail("HOST_ARTIFACT_MISMATCH")


def verify_artifact_closure(measurement_a: VerifiedEnvelope, measurement_b: VerifiedEnvelope, host_record: VerifiedEnvelope) -> ArtifactClosure:
    first, raw, manifest_a, identity_a = _measurement(measurement_a, "artifact_classifier_a")
    second, _, manifest_b, identity_b = _measurement(measurement_b, "artifact_classifier_b")
    host = _record(host_record, _HOST_SCHEMA, "native_host_attestor", _HOST_FIELDS)
    if _lineage(first) != _lineage(second) or _lineage(first) != _lineage(host):
        _fail("LINEAGE_MISMATCH")
    _same_measurement(first, second, raw, manifest_a, manifest_b)
    _diverse(first, second, identity_a, identity_b)
    _host(host, first, raw)
    return ArtifactClosure(first["artifact_slot_id"], first["artifact_kind"], *raw, first["artifact_manifest_payload_sha256"], first["product_manifest_payload_sha256"], (identity_a, identity_b), (first["classifier_implementation_sha256"], second["classifier_implementation_sha256"]), (first["classifier_dependency_set_sha256"], second["classifier_dependency_set_sha256"]), (first["classifier_run_id"], second["classifier_run_id"]))
