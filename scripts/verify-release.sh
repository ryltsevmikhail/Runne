#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s --candidate <directory> [--fixture-only]\n' "$0" >&2
    exit 2
}

FIXTURE_ONLY=0
if [ "$#" -eq 3 ] && [ "$1" = '--fixture-only' ]; then
    FIXTURE_ONLY=1
    shift
fi
[ "$#" -eq 2 ] && [ "$1" = '--candidate' ] || usage
[ -d "$2" ] || { printf 'ERROR: candidate directory is required\n' >&2; exit 2; }
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { printf 'ERROR: must run inside a Git worktree\n' >&2; exit 2; }
SOURCE_REVISION=$(git -C "$REPO_ROOT" rev-parse --verify HEAD^{commit} 2>/dev/null) || { printf 'ERROR: source HEAD is required\n' >&2; exit 2; }
if git -C "$REPO_ROOT" diff --quiet && git -C "$REPO_ROOT" diff --cached --quiet; then SOURCE_CLEAN=1; else SOURCE_CLEAN=0; fi

python3 - "$REPO_ROOT" "$SOURCE_REVISION" "$SOURCE_CLEAN" "$2" "$FIXTURE_ONLY" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import sys
import unicodedata

source_root = pathlib.Path(sys.argv[1]).resolve()
source_revision = sys.argv[2]
source_clean = sys.argv[3] == "1"
candidate_root = pathlib.Path(sys.argv[4]).resolve()
fixture_only = sys.argv[5] == "1"
blocked = []
gate_order = [
    "source-integrity", "source-clean", "profile-integrity", "manifest", "qualification-state", "checksums", "artifact-digest",
    "hosted-platform-evidence", "security-evidence", "performance-evidence", "compatibility",
    "install-upgrade-rollback",
    "phase6b-native-certificate", "phase8-compatibility", "phase9-operations",
    "independent-final-review", "owner-approval", "approval-attestation",
]
allowed_evidence_kinds = {
    "package", "checksums", "provenance-attestation", "sbom",
    "hosted-build-test", "hosted-clippy", "hosted-rustdoc", "hosted-docs",
    "advisory", "license", "secret-scan", "performance", "soak", "chaos",
    "fresh-install", "upgrade", "rollback", "compatibility",
    "phase6b-native-certificate", "phase8-compatibility", "phase9-operations",
    "review-packet", "independent-final-review", "owner-approval", "blocked-gate",
}
supply_chain_gate_ids = {
    "advisory": "advisory",
    "license": "license",
    "secret-scan": "secret-scan",
    "sbom": "sbom",
    "performance": "performance",
    "soak": "soak",
    "chaos": "chaos",
}
operation_kinds = {"fresh-install", "upgrade", "rollback"}
release_operation_schema_revision = "release-operation-evidence.v1"
phase_evidence_schemas = {
    "phase6b-native-certificate": "phase6b-native-certificate.v1",
    "phase8-compatibility": "phase8-compatibility-evidence.v1",
    "phase9-operations": "phase9-operations-evidence.v1",
}

def block(gate):
    if gate not in blocked:
        blocked.append(gate)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"

def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result

def read_json(path):
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("BOM is not allowed")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    if raw != canonical(value):
        raise ValueError("JSON is not canonical")
    return value

def safe_path(value):
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = pathlib.PurePosixPath(value)
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)

def exact_fields(value, fields):
    return isinstance(value, dict) and set(value) == set(fields)

def valid_hex(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None

def canonical_identity(value):
    if not isinstance(value, str):
        return None
    normalized = unicodedata.normalize("NFC", value).strip().casefold()
    return normalized or None

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
    if not exact_fields(payload, required) or payload["schema_revision"] != phase_evidence_schemas[kind] or payload["outcome"] != "passed":
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

def release_operation_payload_is_valid(payload, record, profile_bindings):
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
    if payload["source_schema_revision"] != release_operation_schema_revision or payload["destination_schema_revision"] != release_operation_schema_revision:
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

def candidate_file(relative):
    if not safe_path(relative):
        raise ValueError("unsafe candidate path")
    path = candidate_root.joinpath(*pathlib.PurePosixPath(relative).parts)
    if not path.is_file() or candidate_root not in path.resolve().parents:
        raise ValueError("candidate file is missing")
    return path

def hosted_runner(value):
    fields = {"provider", "runner_image", "run_id"}
    if not exact_fields(value, fields):
        return False
    forbidden = {"local", "localhost", "placeholder", "unspecified", "unknown"}
    return all(isinstance(value[field], str) and value[field].strip() and value[field].strip().lower() not in forbidden for field in fields)

try:
    manifest_path = candidate_root / "release-manifest.v1.json"
    manifest = read_json(manifest_path)
    required = {"format", "candidate", "artifacts", "profiles", "platforms", "evidence", "qualification_state"}
    if not isinstance(manifest, dict) or set(manifest) != required or manifest["format"] != "release-manifest.v1":
        raise ValueError("invalid manifest envelope")
    candidate = manifest["candidate"]
    if not exact_fields(candidate, ("source_revision", "release_version", "lockfile_digest", "qualification_lanes")):
        raise ValueError("invalid candidate tuple")
    if not valid_hex(candidate["source_revision"], 40) or not valid_hex(candidate["lockfile_digest"]):
        raise ValueError("invalid candidate digest")
    if candidate["source_revision"] != source_revision:
        block("source-integrity")
    if not source_clean:
        block("source-clean")
    if not isinstance(candidate["release_version"], str) or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?", candidate["release_version"]):
        raise ValueError("invalid release version")
    candidate_digest = hashlib.sha256(canonical(candidate).rstrip(b"\n")).hexdigest()
    if (source_root / "Cargo.lock").is_file() and digest(source_root / "Cargo.lock") != candidate["lockfile_digest"]:
        block("source-integrity")
    expected_lanes = {"pinned-1.97.1": "1.97.1", "msrv-1.95.0": "1.95.0"}
    lane_slots = {}
    if not isinstance(candidate["qualification_lanes"], list) or len(candidate["qualification_lanes"]) != 2:
        raise ValueError("invalid qualification lanes")
    for lane in candidate["qualification_lanes"]:
        if not exact_fields(lane, ("lane_id", "rustc_version", "cargo_version", "hosted_execution_slots")):
            raise ValueError("invalid qualification lane")
        lane_id = lane["lane_id"]
        if lane_id not in expected_lanes or lane["rustc_version"] != expected_lanes[lane_id] or lane["cargo_version"] != expected_lanes[lane_id]:
            raise ValueError("invalid toolchain lane")
        slots = lane["hosted_execution_slots"]
        if not isinstance(slots, list) or len(slots) != 3:
            raise ValueError("invalid hosted slots")
        lane_slots[lane_id] = {}
        for slot in slots:
            if not isinstance(slot, dict) or set(slot) not in ({"platform", "status"}, {"platform", "status", "hosted_runner"}):
                raise ValueError("invalid hosted slot")
            platform = slot.get("platform")
            if platform not in {"linux", "macos", "windows"} or platform in lane_slots[lane_id] or slot.get("status") not in {"planned", "actual"}:
                raise ValueError("invalid hosted slot identity")
            if slot["status"] == "actual" and not hosted_runner(slot.get("hosted_runner")):
                raise ValueError("missing hosted runner")
            if slot["status"] == "planned" and "hosted_runner" in slot:
                raise ValueError("planned slot has runner")
            lane_slots[lane_id][platform] = slot
    if set(lane_slots) != set(expected_lanes) or any(set(slots) != {"linux", "macos", "windows"} for slots in lane_slots.values()):
        raise ValueError("incomplete hosted slots")

    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("missing artifacts")
    artifact_digests = set()
    artifact_paths = set()
    for artifact in artifacts:
        if not exact_fields(artifact, ("path", "target", "sha256", "kind")) or not safe_path(artifact["path"]) or artifact["path"] in artifact_paths or not valid_hex(artifact["sha256"]):
            raise ValueError("invalid artifact")
        artifact_paths.add(artifact["path"])
        if digest(candidate_file(artifact["path"])) != artifact["sha256"]:
            block("artifact-digest")
        artifact_digests.add(artifact["sha256"])

    profiles = manifest["profiles"]
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("missing profiles")
    profile_digests = []
    profile_bindings = []
    for profile in profiles:
        if not exact_fields(profile, ("name", "revision", "path", "sha256")) or not isinstance(profile["name"], str) or not profile["name"].strip() or not isinstance(profile["revision"], int) or isinstance(profile["revision"], bool) or not safe_path(profile["path"]) or not valid_hex(profile["sha256"]):
            raise ValueError("invalid profile")
        profile_path = candidate_file(profile["path"])
        if digest(profile_path) != profile["sha256"]:
            block("profile-integrity")
        source_profile = source_root / "docs" / "profiles" / pathlib.PurePosixPath(profile["path"]).name
        sidecar = source_profile.with_suffix(".digest")
        if not source_profile.is_file() or not sidecar.is_file() or sidecar.read_text(encoding="utf-8").strip() != f"sha256:{digest(source_profile)}" or digest(source_profile) != profile["sha256"]:
            block("profile-integrity")
        profile_digests.append(profile["sha256"])
        profile_bindings.append({"name": profile["name"], "revision": profile["revision"], "sha256": profile["sha256"]})
    if len(set(profile_digests)) != len(profile_digests):
        raise ValueError("duplicate profile digest")

    checksum_path = candidate_root / "checksums.sha256"
    checksums = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines(keepends=True):
        if not re.fullmatch(r"[0-9a-f]{64}  [^\n]+\n", line):
            raise ValueError("malformed checksum")
        item_digest, relative = line[:-1].split("  ", 1)
        if not safe_path(relative) or relative in checksums:
            raise ValueError("unsafe or duplicate checksum path")
        checksums[relative] = item_digest
    if list(checksums) != sorted(checksums, key=lambda item: item.encode("utf-8")):
        raise ValueError("unsorted checksums")
    actual_files = {path.relative_to(candidate_root).as_posix() for path in candidate_root.rglob("*") if path.is_file() and path.name not in {"checksums.sha256", "release-manifest.v1.json"}}
    if set(checksums) != actual_files:
        raise ValueError("unbound candidate file")
    for relative, expected in checksums.items():
        if digest(candidate_file(relative)) != expected:
            block("checksums")

    platforms = manifest["platforms"]
    if not isinstance(platforms, list) or not platforms:
        raise ValueError("missing platform bindings")
    allowed_targets = {"linux": {"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"}, "macos": {"aarch64-apple-darwin", "x86_64-apple-darwin"}, "windows": {"x86_64-pc-windows-msvc"}}
    platform_keys = set()
    platform_artifacts = {}
    platform_targets = {}
    for platform in platforms:
        if not exact_fields(platform, ("os", "target", "artifact_sha256", "profile_digests")) or platform["os"] not in {"linux", "macos", "windows"} or not valid_hex(platform["artifact_sha256"]) or platform["artifact_sha256"] not in artifact_digests or platform["artifact_sha256"] not in artifact_digests or platform["profile_digests"] != profile_digests:
            raise ValueError("invalid platform binding")
        if platform["target"] not in allowed_targets[platform["os"]]:
            raise ValueError("invalid platform target")
        key = (platform["os"], platform["target"])
        if key in platform_keys:
            raise ValueError("duplicate platform binding")
        if platform["os"] in platform_artifacts or platform["artifact_sha256"] in platform_artifacts.values():
            raise ValueError("platform artifact binding is reused")
        if not any(artifact["sha256"] == platform["artifact_sha256"] and artifact["target"] == platform["target"] for artifact in artifacts):
            raise ValueError("platform target does not match its artifact")
        platform_keys.add(key)
        platform_artifacts[platform["os"]] = platform["artifact_sha256"]
        platform_targets[platform["os"]] = platform["target"]
    qualification_state = manifest["qualification_state"]
    if qualification_state not in {"draft", "assembled", "verified", "review-pending", "approved", "blocked"}:
        raise ValueError("invalid qualification state")
    if qualification_state != "assembled" and set(platform_artifacts) != {"linux", "macos", "windows"}:
        raise ValueError("incomplete platform artifact bindings")

    evidence = manifest["evidence"]
    if not isinstance(evidence, list):
        raise ValueError("invalid evidence")
    evidence_kinds = set()
    review_identities = {}
    hosted_evidence = set()
    operation_evidence = set()
    phase_evidence = set()
    evidence_identities = {}
    hosted_kinds = {"hosted-build-test", "hosted-clippy", "hosted-rustdoc", "hosted-docs"}
    for record in evidence:
        fields = {"gate_id", "kind", "candidate_digest", "source_revision", "platform", "artifact_sha256", "profile_digests", "uri", "sha256"}
        hosted_fields = {"lane_id", "rustc_version", "cargo_version", "hosted_runner"}
        is_hosted = record.get("kind") in hosted_kinds if isinstance(record, dict) else False
        expected_fields = fields | hosted_fields if is_hosted else fields
        if not isinstance(record, dict) or record.get("kind") not in allowed_evidence_kinds or set(record) != expected_fields:
            raise ValueError("unrecognized evidence fields")
        if record["kind"] in supply_chain_gate_ids and record["gate_id"] != supply_chain_gate_ids[record["kind"]]:
            raise ValueError("invalid supply-chain evidence gate")
        if record["candidate_digest"] != candidate_digest or record["source_revision"] != candidate["source_revision"] or record["artifact_sha256"] not in artifact_digests or record["profile_digests"] != profile_digests or not valid_hex(record["sha256"]):
            raise ValueError("unbound evidence")
        if record["platform"] != "all" and record["platform"] not in platform_artifacts:
            raise ValueError("invalid evidence platform")
        if record["platform"] in platform_artifacts and record["artifact_sha256"] != platform_artifacts[record["platform"]]:
            raise ValueError("evidence does not bind its platform artifact")
        prefix = f"candidate://{candidate_root.name}/"
        if not isinstance(record["uri"], str) or not record["uri"].startswith(prefix):
            raise ValueError("invalid evidence URI")
        if digest(candidate_file(record["uri"][len(prefix):])) != record["sha256"]:
            block("artifact-digest")
        evidence_payload = None
        if record["kind"] in {"provenance-attestation", "compatibility", "review-packet", "independent-final-review", "owner-approval"} | operation_kinds | set(phase_evidence_schemas) or (qualification_state != "assembled" and record["kind"] in supply_chain_gate_ids):
            evidence_payload = read_json(candidate_file(record["uri"][len(prefix):]))
        if qualification_state != "assembled" and record["kind"] in supply_chain_gate_ids and not supply_chain_payload_is_valid(record["kind"], evidence_payload, record):
            raise ValueError("invalid supply-chain evidence payload")
        if record["kind"] == "provenance-attestation":
            if not exact_fields(evidence_payload, ("artifact_sha256", "candidate_digest", "profile_digests", "qualification_lanes", "source_revision", "target")) or record["platform"] not in platform_targets or evidence_payload["artifact_sha256"] != record["artifact_sha256"] or evidence_payload["candidate_digest"] != candidate_digest or evidence_payload["profile_digests"] != profile_digests or evidence_payload["qualification_lanes"] != candidate["qualification_lanes"] or evidence_payload["source_revision"] != source_revision or evidence_payload["target"] != platform_targets[record["platform"]]:
                raise ValueError("invalid provenance attestation")
        if record["kind"] in operation_kinds:
            if not release_operation_payload_is_valid(evidence_payload, record, profile_bindings):
                block("install-upgrade-rollback")
            else:
                operation_evidence.add((record["kind"], record["platform"]))
        if record["kind"] == "compatibility":
            rows = evidence_payload.get("rows") if isinstance(evidence_payload, dict) else None
            if not exact_fields(evidence_payload, ("candidate_digest", "source_revision", "rows")) or evidence_payload["candidate_digest"] != candidate_digest or evidence_payload["source_revision"] != source_revision or not isinstance(rows, list) or len(rows) != 3:
                block("compatibility")
                rows = []
            seen_rows = set()
            for row in rows:
                disposition = row.get("disposition") if isinstance(row, dict) else None
                expected_row_fields = {"platform", "disposition", "candidate_digest", "source_revision", "artifact_sha256", "profile_digests"}
                if disposition in {"incompatible", "unsupported"}:
                    expected_row_fields |= {"rationale", "decision"}
                if not exact_fields(row, expected_row_fields) or row["platform"] not in platform_artifacts or disposition not in {"verified", "incompatible", "unsupported", "blocked"} or row["platform"] in seen_rows or row["candidate_digest"] != candidate_digest or row["source_revision"] != source_revision or row["artifact_sha256"] != platform_artifacts[row["platform"]] or row["profile_digests"] != profile_digests:
                    block("compatibility")
                    continue
                if disposition in {"incompatible", "unsupported"} and (not isinstance(row["rationale"], str) or not row["rationale"].strip() or not isinstance(row["decision"], str) or not row["decision"].strip()):
                    block("compatibility")
                if disposition != "verified":
                    block("compatibility")
                seen_rows.add(row["platform"])
            if seen_rows != set(platform_artifacts):
                block("compatibility")
        if record["kind"] in phase_evidence_schemas:
            if not phase_payload_is_valid(record["kind"], evidence_payload, record, profile_bindings):
                block(record["kind"])
            else:
                phase_evidence.add((record["kind"], record["platform"]))
        review_fields = {
            "review-packet": {"candidate_digest", "reviewer_identity", "role", "conflict_declaration", "rubric_version", "review_subject_digest"},
            "independent-final-review": {"candidate_digest", "reviewer_identity", "role", "conflict_declaration", "rubric_version", "decision", "review_subject_digest", "attestation"},
            "owner-approval": {"candidate_digest", "owner_identity", "role", "rubric_version", "decision", "review_subject_digest", "attestation"},
        }
        if record["kind"] in review_fields:
            if not isinstance(evidence_payload, dict) or set(evidence_payload) != review_fields[record["kind"]] or evidence_payload.get("candidate_digest") != candidate_digest:
                raise ValueError("invalid review evidence")
            if evidence_payload.get("review_subject_digest") != review_subject_digest(manifest):
                raise ValueError("review subject digest mismatch")
            identity_key = "owner_identity" if record["kind"] == "owner-approval" else "reviewer_identity"
            if canonical_identity(evidence_payload.get(identity_key)) is None:
                raise ValueError("missing review identity")
            if not isinstance(evidence_payload.get("role"), str) or not evidence_payload["role"].strip():
                raise ValueError("missing review role")
            if not isinstance(evidence_payload.get("rubric_version"), str) or not evidence_payload["rubric_version"].strip():
                raise ValueError("missing review rubric version")
            if record["kind"] != "owner-approval":
                if evidence_payload.get("conflict_declaration") != "none":
                    raise ValueError("incomplete review evidence")
            if record["kind"] == "independent-final-review" and evidence_payload["role"] != "security-reliability":
                raise ValueError("final review must cover security and reliability")
            if record["kind"] in {"independent-final-review", "owner-approval"} and evidence_payload.get("decision") != "approved":
                raise ValueError("review decision is not approved")
            if record["kind"] in {"independent-final-review", "owner-approval"}:
                attestation = evidence_payload.get("attestation")
                if not exact_fields(attestation, ("format", "issuer", "subject", "verification")) or attestation["format"] != "release-approval-attestation.v1" or not isinstance(attestation["issuer"], str) or not attestation["issuer"].strip() or attestation["issuer"].strip().casefold() in {"local", "localhost", "placeholder", "unknown", "unspecified"} or attestation["verification"] != "external-cryptographic-verification-required" or attestation["subject"] != approval_attestation_subject(record["kind"], evidence_payload, attestation["issuer"], candidate_digest, review_subject_digest(manifest)):
                    raise ValueError("invalid approval attestation")
                if fixture_only and attestation["issuer"] != "fixture-review-authority":
                    raise ValueError("untrusted fixture approval issuer")
            review_identities[record["kind"]] = canonical_identity(evidence_payload[identity_key])
        if is_hosted:
            lane_id = record["lane_id"]
            slot = lane_slots.get(lane_id, {}).get(record["platform"])
            if slot is None or slot.get("status") != "actual" or record["rustc_version"] != expected_lanes[lane_id] or record["cargo_version"] != expected_lanes[lane_id] or record["hosted_runner"] != slot.get("hosted_runner"):
                raise ValueError("hosted evidence does not match its execution slot")
            identity = (record["kind"], lane_id, record["platform"])
            if identity in hosted_evidence:
                raise ValueError("duplicate hosted evidence")
            hosted_evidence.add(identity)
        identity = (record["kind"], record["gate_id"], record["platform"], record["artifact_sha256"], record.get("lane_id"))
        previous = evidence_identities.get(identity)
        if previous is not None and previous != record["sha256"]:
            raise ValueError("duplicate evidence identity with divergent bytes")
        evidence_identities[identity] = record["sha256"]
        evidence_kinds.add(record["kind"])

    if qualification_state == "draft":
        if evidence or any(slot["status"] != "planned" for slots in lane_slots.values() for slot in slots.values()):
            raise ValueError("invalid draft state")
    assembled_kinds = {"package", "checksums", "provenance-attestation", "sbom"}
    verified_kinds = assembled_kinds | hosted_kinds | {"advisory", "license", "secret-scan", "performance", "soak", "chaos", "fresh-install", "upgrade", "rollback", "compatibility", "phase6b-native-certificate", "phase8-compatibility", "phase9-operations"}
    if qualification_state == "assembled":
        if any(slot["status"] != "planned" for slots in lane_slots.values() for slot in slots.values()):
            raise ValueError("invalid assembled state")
        if not evidence_kinds.issubset(assembled_kinds):
            raise ValueError("invalid assembled evidence")
        for platform in platform_artifacts:
            if not {"package", "checksums", "provenance-attestation", "sbom"}.issubset({record["kind"] for record in evidence if record["platform"] == platform}):
                raise ValueError("incomplete assembled state")
    if qualification_state in {"verified", "review-pending", "approved"}:
        if any(slot["status"] != "actual" for slots in lane_slots.values() for slot in slots.values()):
            raise ValueError("incomplete verified state")
        if not verified_kinds.issubset(evidence_kinds):
            raise ValueError("incomplete verified evidence")
        for platform in platform_artifacts:
            if not assembled_kinds.issubset({record["kind"] for record in evidence if record["platform"] == platform}):
                raise ValueError("missing assembled evidence for platform")
    if qualification_state == "verified" and not evidence_kinds.issubset(verified_kinds):
        raise ValueError("invalid verified evidence")
    if qualification_state in {"review-pending", "approved"} and "review-packet" not in evidence_kinds:
        raise ValueError("missing review packet")
    if qualification_state == "review-pending" and not evidence_kinds.issubset(verified_kinds | {"review-packet"}):
        raise ValueError("invalid pending-review evidence")
    if qualification_state == "blocked" and "blocked-gate" not in evidence_kinds:
        raise ValueError("blocked state requires blocked-gate evidence")
    if qualification_state == "approved":
        if not {"review-packet", "independent-final-review", "owner-approval"}.issubset(evidence_kinds) or not evidence_kinds.issubset(verified_kinds | {"review-packet", "independent-final-review", "owner-approval"}):
            raise ValueError("invalid approved evidence")
        if review_identities.get("independent-final-review") == review_identities.get("owner-approval"):
            raise ValueError("owner cannot independently final-review")

except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
    if "checksum" in str(error):
        block("checksums")
    else:
        block("manifest")
    candidate_digest = None
    evidence_kinds = set()
    lane_slots = {}
    hosted_evidence = set()
    operation_evidence = set()
    phase_evidence = set()
    qualification_state = None

# Evidence gates are deliberately evaluated even when local structural checks failed.
hosted_complete = all(
    lane_slots.get(lane, {}).get(platform, {}).get("status") == "actual"
    for lane in ("pinned-1.97.1", "msrv-1.95.0") for platform in ("linux", "macos", "windows")
)
required_hosted_evidence = {
    (kind, lane, platform)
    for kind in ("hosted-build-test", "hosted-clippy", "hosted-rustdoc", "hosted-docs")
    for lane in ("pinned-1.97.1", "msrv-1.95.0")
    for platform in ("linux", "macos", "windows")
}
if not fixture_only or not hosted_complete or not required_hosted_evidence.issubset(hosted_evidence):
    block("hosted-platform-evidence")
if not {"advisory", "license", "secret-scan", "sbom"}.issubset(evidence_kinds):
    block("security-evidence")
if not {"performance", "soak", "chaos"}.issubset(evidence_kinds):
    block("performance-evidence")
if not {"fresh-install", "upgrade", "rollback", "compatibility"}.issubset(evidence_kinds):
    block("compatibility")
if not {
    (kind, platform)
    for kind in operation_kinds
    for platform in ("linux", "macos", "windows")
}.issubset(operation_evidence):
    block("install-upgrade-rollback")
for kind in ("phase6b-native-certificate", "phase8-compatibility", "phase9-operations"):
    if not {(kind, platform) for platform in ("linux", "macos", "windows")}.issubset(phase_evidence):
        block(kind)
for kind in ("independent-final-review", "owner-approval"):
    if kind not in evidence_kinds:
        block(kind)
if not fixture_only and qualification_state == "approved":
    block("approval-attestation")
if qualification_state != "approved":
    block("qualification-state")

blocked.sort(key=gate_order.index)
status = "blocked" if blocked else ("fixture-verified" if fixture_only else "verified")
print(json.dumps({"blocked_gate_ids": blocked, "status": status}, sort_keys=True, separators=(",", ":")))
PY
