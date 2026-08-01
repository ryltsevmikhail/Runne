import hashlib
import json

from .constants import PHASE_EVIDENCE_SCHEMAS, RELEASE_OPERATION_SCHEMA_REVISION
from .io import canonical, digest, exact_fields, read_json, valid_hex

def review_subject_digest(manifest):
    """Bind reviews to immutable release inputs, excluding state and recursive decisions."""
    subject = {
        "format": manifest["format"],
        "candidate": manifest["candidate"],
        "artifacts": manifest["artifacts"],
        "profiles": manifest["profiles"],
        "platforms": manifest["platforms"],
        "evidence": [
            record for record in manifest["evidence"]
            if record["kind"] not in {"review-packet", "independent-final-review", "owner-approval"}
        ],
    }
    return hashlib.sha256(canonical(subject).rstrip(b"\n")).hexdigest()

def approval_attestation_subject(kind, payload, attestation_issuer, candidate_digest, subject_digest):
    """Return the exact signed approval subject for one decision authority."""
    identity_key = "owner_identity" if kind == "owner-approval" else "reviewer_identity"
    return {
        "candidate_digest": candidate_digest,
        "review_subject_digest": subject_digest,
        "kind": kind,
        "issuer": attestation_issuer,
        "issuer_identity": payload[identity_key],
        "role": payload["role"],
        "decision": payload["decision"],
        "rubric_version": payload["rubric_version"],
    }

def phase_payload_is_valid(kind, payload, record, profiles):
    common = {"schema_revision", "candidate_digest", "source_revision", "platform", "artifact_sha256", "profile_digests", "outcome"}
    required = {
        "phase6b-native-certificate": common | {"native_certificate_sha256", "containment_outcome", "startup_outcome"},
        "phase8-compatibility": common | {"profile_name", "profile_revision", "profile_sha256", "compatibility_outcome"},
        "phase9-operations": common | {"evaluation_report_sha256", "observability_report_sha256", "operations_report_sha256"},
    }[kind]
    if not exact_fields(payload, required) or payload["schema_revision"] != PHASE_EVIDENCE_SCHEMAS[kind] or payload["outcome"] != "passed":
        return False
    for field in ("candidate_digest", "source_revision", "platform", "artifact_sha256", "profile_digests"):
        if payload[field] != record[field]:
            return False
    if kind == "phase6b-native-certificate":
        return valid_hex(payload["native_certificate_sha256"]) and payload["containment_outcome"] == "passed" and payload["startup_outcome"] == "passed"
    if kind == "phase8-compatibility":
        return (
            payload["compatibility_outcome"] == "passed"
            and any(profile == {"name": payload["profile_name"], "revision": payload["profile_revision"], "sha256": payload["profile_sha256"]} for profile in profiles)
        )
    return all(valid_hex(payload[field]) for field in ("evaluation_report_sha256", "observability_report_sha256", "operations_report_sha256"))

def supply_chain_payload_is_valid(kind, payload, record):
    common = {"artifact_sha256", "candidate_digest", "outcome", "profile_digests", "source_revision"}
    required = {
        "advisory": common | {"advisory_database_sha256", "findings"},
        "license": common | {"findings", "policy_revision"},
        "secret-scan": common | {"findings", "scanner_version"},
        "sbom": common | {"bomFormat", "components", "specVersion"},
        "performance": common | {"metric_set_sha256"},
        "soak": common | {"duration_seconds"},
        "chaos": common | {"scenario_set_sha256"},
    }[kind]
    if not exact_fields(payload, required) or payload["outcome"] != "passed":
        return False
    for field in ("artifact_sha256", "candidate_digest", "source_revision", "profile_digests"):
        if payload[field] != record[field]:
            return False
    if kind == "advisory":
        return valid_hex(payload["advisory_database_sha256"]) and isinstance(payload["findings"], list) and not payload["findings"]
    if kind == "license":
        return isinstance(payload["policy_revision"], str) and payload["policy_revision"].strip() and isinstance(payload["findings"], list) and not payload["findings"]
    if kind == "secret-scan":
        return isinstance(payload["scanner_version"], str) and payload["scanner_version"].strip() and isinstance(payload["findings"], list) and not payload["findings"]
    if kind == "sbom":
        return payload["bomFormat"] == "CycloneDX" and payload["specVersion"] == "1.5" and isinstance(payload["components"], list)
    if kind in {"performance", "chaos"}:
        key = "metric_set_sha256" if kind == "performance" else "scenario_set_sha256"
        return valid_hex(payload[key])
    return isinstance(payload["duration_seconds"], int) and not isinstance(payload["duration_seconds"], bool) and payload["duration_seconds"] > 0

def release_operation_payload_is_valid(payload, record, profile_bindings, candidate_root, candidate_file):
    required = {
        "candidate_digest", "source_revision", "platform", "outcome",
        "source_artifact_sha256", "destination_artifact_sha256",
        "source_profiles", "destination_profiles",
        "source_schema_revision", "destination_schema_revision",
        "source_candidate_digest", "source_candidate_revision",
        "source_candidate_manifest_uri", "source_candidate_manifest_sha256",
    }
    if not exact_fields(payload, required) or payload["candidate_digest"] != record["candidate_digest"] or payload["source_revision"] != record["source_revision"] or payload["platform"] != record["platform"] or payload["outcome"] != "passed":
        return False
    if not valid_hex(payload["source_artifact_sha256"]) or payload["destination_artifact_sha256"] != record["artifact_sha256"]:
        return False
    if payload["source_schema_revision"] != RELEASE_OPERATION_SCHEMA_REVISION or payload["destination_schema_revision"] != RELEASE_OPERATION_SCHEMA_REVISION:
        return False
    def valid_profile_bindings(bindings, nonempty=False):
        return isinstance(bindings, list) and all(
            exact_fields(binding, ("name", "revision", "sha256"))
            and isinstance(binding["name"], str) and binding["name"].strip()
            and isinstance(binding["revision"], int) and not isinstance(binding["revision"], bool)
            and valid_hex(binding["sha256"])
            for binding in bindings
        ) and (not nonempty or bool(bindings)) and len({(binding["name"], binding["revision"]) for binding in bindings}) == len(bindings)
    if not valid_profile_bindings(payload["source_profiles"], nonempty=True) or not valid_profile_bindings(payload["destination_profiles"]) or payload["destination_profiles"] != profile_bindings:
        return False
    prefix = f"candidate://{candidate_root.name}/"
    if not valid_hex(payload["source_candidate_digest"]) or not valid_hex(payload["source_candidate_revision"], 40) or not valid_hex(payload["source_candidate_manifest_sha256"]) or not isinstance(payload["source_candidate_manifest_uri"], str) or not payload["source_candidate_manifest_uri"].startswith(prefix):
        return False
    try:
        source_manifest_path = candidate_file(payload["source_candidate_manifest_uri"][len(prefix):])
        if digest(source_manifest_path) != payload["source_candidate_manifest_sha256"]:
            return False
        source_manifest = read_json(source_manifest_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        return False
    if not exact_fields(source_manifest, ("format", "candidate_digest", "source_revision", "artifacts", "profiles")) or source_manifest["format"] != "source-candidate-reference.v1" or source_manifest["candidate_digest"] != payload["source_candidate_digest"] or source_manifest["source_revision"] != payload["source_candidate_revision"] or not isinstance(source_manifest["artifacts"], list) or not isinstance(source_manifest["profiles"], list):
        return False
    source_artifacts = {}
    for artifact in source_manifest["artifacts"]:
        if not exact_fields(artifact, ("platform", "sha256")) or artifact["platform"] in source_artifacts or not valid_hex(artifact["sha256"]):
            return False
        source_artifacts[artifact["platform"]] = artifact["sha256"]
    if source_artifacts.get(record["platform"]) != payload["source_artifact_sha256"]:
        return False
    if not valid_profile_bindings(source_manifest["profiles"], nonempty=True) or source_manifest["profiles"] != payload["source_profiles"]:
        return False
    return True

def hosted_runner(value):
    fields = {"provider", "runner_image", "run_id"}
    if not exact_fields(value, fields):
        return False
    forbidden = {"local", "localhost", "placeholder", "unspecified", "unknown"}
    return all(isinstance(value[field], str) and value[field].strip() and value[field].strip().lower() not in forbidden for field in fields)
