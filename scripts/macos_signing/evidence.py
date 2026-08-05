import json
import re
from pathlib import Path
from typing import Sequence

from .execution import dispositions, execution_records, expected_records
from .models import (
    CandidateIdentity, CommandResult, CommandSpec, Disposition, EvidenceCandidate, EvidenceEntitlements,
    EvidenceTarget, ExecutionRecord, FailureCode, SignatureExpectation, SignatureIdentity, SigningEvidence,
    SigningFailure, SigningProfile,
)
from .observations import _checked_observations, parse_designated_requirement, parse_embedded_entitlements, parse_signature_metadata
from .state import CandidateStage, CandidateState

_SCHEMA_VERSION = "evidence-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SYNTHETIC = "SYNTHETIC_ONLY"


def build_development_evidence(
    candidate: CandidateIdentity, platform: str, target: EvidenceTarget, commands: Sequence[CommandSpec],
    results: Sequence[CommandResult], snapshot_stage: str,
) -> SigningEvidence:
    signature = SignatureIdentity("development-ad-hoc", "SYNTHETIC", "ad-hoc", "designated => identifier development-ad-hoc", None)
    return _assemble(candidate, signature, SigningProfile.DEVELOPMENT_AD_HOC, platform, target, commands, results, snapshot_stage)


def build_production_evidence_from_results(
    state: CandidateState, daemon_expectation: SignatureExpectation, app_expectation: SignatureExpectation,
    platform: str, target: EvidenceTarget, commands: Sequence[CommandSpec], results: Sequence[CommandResult],
) -> SigningEvidence | SigningFailure:
    if not isinstance(state, CandidateState) or state.stage is not CandidateStage.STAPLED:
        return _failure(FailureCode.EVIDENCE_INCOMPLETE)
    observations = _production_observations(commands, results, daemon_expectation, app_expectation)
    if isinstance(observations, FailureCode):
        return _failure(observations)
    try:
        return _assemble(state.candidate.candidate, observations.app, SigningProfile.PRODUCTION_DEVELOPER_ID, platform, target, commands, results, state.stage.value)
    except (TypeError, ValueError):
        return _failure(FailureCode.EVIDENCE_INCOMPLETE)


def normalize_evidence(evidence: SigningEvidence) -> bytes:
    if not isinstance(evidence, SigningEvidence) or not _complete(evidence) or not _serializable(evidence):
        raise ValueError("invalid evidence")
    identity, signature = evidence.candidate.identity, evidence.candidate.signature
    signature_payload = {"bundle_id": signature.bundle_id, "authority_class": signature.authority_class, "designated_requirement": signature.designated_requirement}
    if evidence.profile is SigningProfile.PRODUCTION_DEVELOPER_ID:
        signature_payload.update({"team_identifier": signature.team_identifier, "cdhash": signature.cdhash})
    payload = {
        "schema_version": evidence.schema_version,
        "candidate": {"relative_name": identity.relative_name, "tree_sha256": identity.tree_sha256, "main_sha256": identity.main_sha256, "daemon_sha256": identity.daemon_sha256, "release_candidate_sha256": identity.release_candidate_sha256, "signature": signature_payload},
        "profile": evidence.profile.value, "platform": evidence.platform,
        "target": {"candidate": evidence.target.candidate, "main": evidence.target.main, "daemon": evidence.target.daemon},
        "entitlements": {"app_sha256": evidence.entitlements.app_sha256, "daemon_sha256": evidence.entitlements.daemon_sha256},
        "commands": [_record_payload(record) for record in evidence.commands], "stapling": evidence.stapling,
        "gatekeeper": evidence.gatekeeper, "disposition": evidence.disposition, "snapshot_stage": evidence.snapshot_stage,
    }
    if evidence.profile is SigningProfile.PRODUCTION_DEVELOPER_ID:
        payload["notarization"] = evidence.notarization
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def validate_production_evidence(evidence: SigningEvidence, candidate: CandidateIdentity, expected_signature: SignatureExpectation, expected_platform: str, expected_target: EvidenceTarget) -> SigningFailure:
    if not isinstance(evidence, SigningEvidence) or not isinstance(candidate, CandidateIdentity):
        return _failure(FailureCode.EVIDENCE_INCOMPLETE)
    if evidence.profile is SigningProfile.DEVELOPMENT_AD_HOC:
        return _failure(FailureCode.PROFILE_DOWNGRADE_REJECTED)
    if evidence.profile is not SigningProfile.PRODUCTION_DEVELOPER_ID or not _structural_complete(evidence):
        return _failure(FailureCode.EVIDENCE_INCOMPLETE)
    try:
        expected = _expected_signature(expected_signature)
    except ValueError:
        return _failure(FailureCode.EVIDENCE_INCOMPLETE)
    if evidence.candidate.identity != candidate or evidence.candidate.signature != expected or not _target_bound(candidate, expected_target):
        return _failure(FailureCode.ARTIFACT_IDENTITY_MISMATCH)
    if not _safe_text(expected_platform) or evidence.snapshot_stage != CandidateStage.STAPLED.value:
        return _failure(FailureCode.EVIDENCE_INCOMPLETE)
    if evidence.platform != expected_platform or evidence.target != expected_target:
        return _failure(FailureCode.ARTIFACT_IDENTITY_MISMATCH)
    if evidence.entitlements != EvidenceEntitlements(candidate.app_entitlements_sha256, candidate.daemon_entitlements_sha256):
        return _failure(FailureCode.ARTIFACT_IDENTITY_MISMATCH)
    record_failure = _record_failure(evidence.commands, expected_target, candidate)
    if record_failure:
        return _failure(record_failure)
    disposition_failure = _disposition_failure(evidence, dispositions(evidence.commands))
    return _failure(disposition_failure or FailureCode.BLOCKED_CREDENTIALS)


def _production_observations(commands, results, daemon_expectation, app_expectation):
    if not isinstance(daemon_expectation, SignatureExpectation) or not isinstance(app_expectation, SignatureExpectation):
        return FailureCode.EVIDENCE_INCOMPLETE
    required = ("metadata-daemon", "requirement-daemon", "entitlements-daemon", "metadata-app", "requirement-app", "entitlements-app")
    if len(commands) != len(results) or any(sum(command.phase == phase for command in commands) != 1 for phase in required):
        return FailureCode.EVIDENCE_INCOMPLETE
    pairs = dict(zip((command.phase for command in commands), results)) if len(commands) == len(results) else {}
    values = []
    for suffix, expectation in (("daemon", daemon_expectation), ("app", app_expectation)):
        metadata = parse_signature_metadata(pairs.get("metadata-" + suffix))
        requirement = parse_designated_requirement(pairs.get("requirement-" + suffix))
        entitlements = parse_embedded_entitlements(pairs.get("entitlements-" + suffix))
        if isinstance(metadata, FailureCode):
            return metadata
        if isinstance(requirement, FailureCode):
            return requirement
        if entitlements:
            return entitlements
        values.extend((metadata, requirement))
    checked = _checked_observations(values[0], values[2], values[1], values[3], daemon_expectation, app_expectation)
    return checked


def _assemble(candidate, signature, profile, platform, target, commands, results, snapshot_stage):
    if not _identity_complete(candidate) or not isinstance(profile, SigningProfile) or not _safe_text(platform) or not _target_bound(candidate, target) or not _signature_complete(signature):
        raise ValueError("invalid evidence input")
    records = execution_records(commands, results, target)
    notarization, stapling, gatekeeper = dispositions(records)
    disposition = Disposition.DEVELOPMENT_ONLY.value if profile is SigningProfile.DEVELOPMENT_AD_HOC else _SYNTHETIC
    return SigningEvidence(_SCHEMA_VERSION, EvidenceCandidate(candidate, signature), profile, platform, target, EvidenceEntitlements(candidate.app_entitlements_sha256, candidate.daemon_entitlements_sha256), records, notarization, stapling, gatekeeper, disposition, snapshot_stage)


def _record_failure(records, target, candidate):
    expected = expected_records(target, candidate)
    for record in expected:
        if record.phase not in {item.phase for item in records}:
            return _missing_phase(record.phase)
    if len(records) != len(expected):
        return FailureCode.ARTIFACT_IDENTITY_MISMATCH
    for actual, required in zip(records, expected):
        if actual != required:
            return FailureCode.ARTIFACT_IDENTITY_MISMATCH
        if actual.outcome != "success":
            return _failed_phase(actual.phase)
    return None


def _missing_phase(phase):
    if phase.startswith("notary-"):
        return FailureCode.NOTARIZATION_NOT_RUN
    if phase.startswith("staple-"):
        return FailureCode.STAPLE_NOT_RUN
    return FailureCode.GATEKEEPER_ASSESSMENT_FAILED if phase == "gatekeeper" else FailureCode.EVIDENCE_INCOMPLETE


def _failed_phase(phase):
    if phase.startswith("notary-"):
        return FailureCode.NOTARIZATION_FAILED
    if phase.startswith("staple-"):
        return FailureCode.STAPLE_FAILED
    return FailureCode.GATEKEEPER_ASSESSMENT_FAILED if phase == "gatekeeper" else FailureCode.SIGNATURE_INVALID


def _record_payload(record: ExecutionRecord) -> dict[str, str | bool | None]:
    return {"phase": record.phase, "operation": record.operation, "target": record.target, "hardened_runtime": record.hardened_runtime, "entitlement_sha256": record.entitlement_sha256, "outcome": record.outcome}


def _disposition_failure(evidence, expected):
    for value, required, absent, failed in zip((evidence.notarization, evidence.stapling, evidence.gatekeeper), expected, (FailureCode.NOTARIZATION_NOT_RUN, FailureCode.STAPLE_NOT_RUN, FailureCode.GATEKEEPER_ASSESSMENT_FAILED), (FailureCode.NOTARIZATION_FAILED, FailureCode.STAPLE_FAILED, FailureCode.GATEKEEPER_ASSESSMENT_FAILED)):
        if value != required:
            return absent if not value else failed
    return None


def _complete(evidence):
    return _structural_complete(evidence) and _target_bound(evidence.candidate.identity, evidence.target)


def _structural_complete(evidence):
    return isinstance(evidence, SigningEvidence) and evidence.schema_version == _SCHEMA_VERSION and isinstance(evidence.profile, SigningProfile) and _safe_text(evidence.platform) and _identity_complete(evidence.candidate.identity) and _signature_complete(evidence.candidate.signature) and _target_complete(evidence.target) and all(_sha256(value) for value in (evidence.entitlements.app_sha256, evidence.entitlements.daemon_sha256)) and isinstance(evidence.commands, tuple) and all(_record_complete(record) for record in evidence.commands) and all(isinstance(value, str) for value in (evidence.notarization, evidence.stapling, evidence.gatekeeper, evidence.disposition, evidence.snapshot_stage))


def _serializable(evidence):
    return (evidence.notarization, evidence.stapling, evidence.gatekeeper).count("accepted") + (evidence.notarization, evidence.stapling, evidence.gatekeeper).count("not-run") == 3 and evidence.disposition in {Disposition.DEVELOPMENT_ONLY.value, _SYNTHETIC}


def _identity_complete(identity):
    return isinstance(identity, CandidateIdentity) and _candidate_name(identity.relative_name) and all(_sha256(value) for value in (identity.tree_sha256, identity.main_sha256, identity.daemon_sha256, identity.release_candidate_sha256, identity.app_entitlements_sha256, identity.daemon_entitlements_sha256))


def _signature_complete(signature):
    return isinstance(signature, SignatureIdentity) and all(_safe_text(value) for value in (signature.bundle_id, signature.team_identifier, signature.authority_class, signature.designated_requirement)) and (signature.cdhash is None or _safe_text(signature.cdhash))


def _expected_signature(signature):
    if not isinstance(signature, SignatureExpectation):
        raise ValueError("invalid signature expectation")
    expected = SignatureIdentity(signature.bundle_id, signature.team_identifier, signature.authority_class, signature.designated_requirement, signature.cdhash)
    if not _signature_complete(expected):
        raise ValueError("invalid signature expectation")
    return expected


def _target_complete(target):
    if not isinstance(target, EvidenceTarget) or not _candidate_name(target.candidate):
        return False
    main, daemon = Path(target.main), Path(target.daemon)
    return _relative(target.main) and _relative(target.daemon) and main.parts[:2] == ("Contents", "MacOS") and len(main.parts) == 3 and main.name != "gocoded" and daemon.parts == ("Contents", "MacOS", "gocoded")


def _target_bound(identity, target):
    return _identity_complete(identity) and _target_complete(target) and identity.relative_name == target.candidate


def _candidate_name(value):
    return _relative(value, single=True) and Path(value).suffix == ".app"


def _record_complete(record):
    return isinstance(record, ExecutionRecord) and all(_safe_text(value) for value in (record.phase, record.operation, record.outcome)) and _relative(record.target) and type(record.hardened_runtime) is bool and (record.entitlement_sha256 is None or _sha256(record.entitlement_sha256))


def _relative(value, single=False):
    path = Path(value) if isinstance(value, str) else Path()
    return isinstance(value, str) and bool(value) and not path.is_absolute() and ".." not in path.parts and (not single or len(path.parts) == 1)


def _safe_text(value):
    return isinstance(value, str) and bool(value) and "/" not in value and "\\" not in value and "\n" not in value and "\r" not in value


def _sha256(value):
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _failure(code):
    return SigningFailure(code, "evidence", "")
