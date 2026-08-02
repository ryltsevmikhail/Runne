import json

from .artifacts import validate_artifacts_and_profiles
from .candidate import validate_candidate
from .constants import HOSTED_KINDS
from .evidence import validate_evidence
from .io import candidate_file_for
from .platforms import validate_platforms
from .qualification import validate_qualification

def verify_manifest(source_root, source_revision, source_clean, candidate_root, fixture_only, block):
    candidate_file = lambda relative: candidate_file_for(candidate_root, relative)
    evidence_kinds = set()
    lane_slots = {}
    hosted_evidence = set()
    operation_evidence = set()
    phase_evidence = set()
    qualification_state = None
    try:
        manifest, candidate, candidate_digest, lane_slots = validate_candidate(
            source_root, source_revision, source_clean, candidate_root, block
        )
        artifacts, artifact_digests, profile_digests, profile_bindings = (
            validate_artifacts_and_profiles(
                source_root, manifest, candidate_root, candidate_file, block
            )
        )
        platform_artifacts, platform_targets, qualification_state = validate_platforms(
            manifest, artifacts, artifact_digests, profile_digests
        )
        (
            evidence_kinds,
            review_identities,
            hosted_evidence,
            operation_evidence,
            phase_evidence,
        ) = validate_evidence(
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
        )
        validate_qualification(
            qualification_state,
            manifest["evidence"],
            evidence_kinds,
            lane_slots,
            platform_artifacts,
            review_identities,
            HOSTED_KINDS,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        if "checksum" in str(error):
            block("checksums")
        else:
            block("manifest")
        evidence_kinds = set()
        lane_slots = {}
        hosted_evidence = set()
        operation_evidence = set()
        phase_evidence = set()
        qualification_state = None

    return {
        "evidence_kinds": evidence_kinds,
        "lane_slots": lane_slots,
        "hosted_evidence": hosted_evidence,
        "operation_evidence": operation_evidence,
        "phase_evidence": phase_evidence,
        "qualification_state": qualification_state,
    }
