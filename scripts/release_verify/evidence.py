from .constants import (
    ALLOWED_EVIDENCE_KINDS,
    EXPECTED_LANES,
    OPERATION_KINDS,
    PHASE_EVIDENCE_SCHEMAS,
    SUPPLY_CHAIN_GATE_IDS,
)
from .io import canonical_identity, digest, exact_fields, read_json, valid_hex
from .payloads import (
    approval_attestation_subject,
    phase_payload_is_valid,
    release_operation_payload_is_valid,
    review_subject_digest,
    supply_chain_payload_is_valid,
)

def validate_evidence(
    manifest,
    candidate,
    candidate_digest,
    source_revision,
    artifact_digests,
    profile_digests,
    profile_bindings,
    platform_artifacts,
    platform_targets,
    lane_slots,
    qualification_state,
    candidate_root,
    candidate_file,
    fixture_only,
    block,
):
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
        if not isinstance(record, dict) or record.get("kind") not in ALLOWED_EVIDENCE_KINDS or set(record) != expected_fields:
            raise ValueError("unrecognized evidence fields")
        if record["kind"] in SUPPLY_CHAIN_GATE_IDS and record["gate_id"] != SUPPLY_CHAIN_GATE_IDS[record["kind"]]:
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
        if record["kind"] in {"provenance-attestation", "compatibility", "review-packet", "independent-final-review", "owner-approval"} | OPERATION_KINDS | set(PHASE_EVIDENCE_SCHEMAS) or (qualification_state != "assembled" and record["kind"] in SUPPLY_CHAIN_GATE_IDS):
            evidence_payload = read_json(candidate_file(record["uri"][len(prefix):]))
        if qualification_state != "assembled" and record["kind"] in SUPPLY_CHAIN_GATE_IDS and not supply_chain_payload_is_valid(record["kind"], evidence_payload, record):
            raise ValueError("invalid supply-chain evidence payload")
        if record["kind"] == "provenance-attestation":
            if not exact_fields(evidence_payload, ("artifact_sha256", "candidate_digest", "profile_digests", "qualification_lanes", "source_revision", "target")) or record["platform"] not in platform_targets or evidence_payload["artifact_sha256"] != record["artifact_sha256"] or evidence_payload["candidate_digest"] != candidate_digest or evidence_payload["profile_digests"] != profile_digests or evidence_payload["qualification_lanes"] != candidate["qualification_lanes"] or evidence_payload["source_revision"] != source_revision or evidence_payload["target"] != platform_targets[record["platform"]]:
                raise ValueError("invalid provenance attestation")
        if record["kind"] in OPERATION_KINDS:
            if not release_operation_payload_is_valid(evidence_payload, record, profile_bindings, candidate_root, candidate_file):
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
        if record["kind"] in PHASE_EVIDENCE_SCHEMAS:
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
            if slot is None or slot.get("status") != "actual" or record["rustc_version"] != EXPECTED_LANES[lane_id] or record["cargo_version"] != EXPECTED_LANES[lane_id] or record["hosted_runner"] != slot.get("hosted_runner"):
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
    return evidence_kinds, review_identities, hosted_evidence, operation_evidence, phase_evidence
