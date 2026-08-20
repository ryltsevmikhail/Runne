"""Ingestion of macOS production signing evidence.

`ingest_production_evidence` — единственная точка входа: проверяет
production evidence документ против схемы, канонических фаз исполнения,
связанных identity/expectation и целостности дайджеста. Функция никогда
не поднимает исключений; любая ошибка возвращается как `IngestionResult`
со статусом `REJECTED`.

Инварианты чистоты: модуль не читает переменные окружения, не запускает
внешние процессы, не выполняет сетевых операций и не записывает файлы.
Redaction-контракт: `SigningFailure` несёт только код и фазу, `candidate_id`
всегда пуст; значения из payload никогда не попадают в результат.
"""

import re
from dataclasses import dataclass
from enum import StrEnum

from .execution import expected_records
from .ingestion_rules import (
    AD_HOC_PROFILE,
    CANONICAL_PHASES,
    ENVIRONMENT_CLASS,
    AUTHENTICITY_METHOD,
    KIND,
    PLATFORM,
    PRODUCER_LANE,
    PROFILE,
    SCHEMA_VERSION,
    SYNTHETIC_ENVIRONMENT_CLASSES,
    SYNTHETIC_KIND,
    SYNTHETIC_SCHEMA_VERSION,
    evidence_digest,
    freshness_ok,
    scan_secrets,
    sha256_ok,
)
from .models import CandidateIdentity, EvidenceTarget, FailureCode, SignatureExpectation, SigningFailure

_TOP_LEVEL_FIELDS = (
    "schema_version",
    "kind",
    "profile",
    "platform",
    "environment_class",
    "authenticity_method",
    "producer_lane",
    "candidate",
    "signature",
    "target",
    "entitlements",
    "commands",
    "notarization",
    "stapling",
    "gatekeeper",
    "produced_at",
    "fresh_until",
    "review",
    "evidence_sha256",
)
_CANDIDATE_FIELDS = ("relative_name", "tree_sha256", "main_sha256", "daemon_sha256", "release_candidate_sha256", "app_entitlements_sha256", "daemon_entitlements_sha256")
_SIGNATURE_FIELDS = ("bundle_id", "team_identifier", "authority_class", "designated_requirement", "cdhash")
_TARGET_FIELDS = ("candidate", "main", "daemon")
_ENTITLEMENTS_FIELDS = ("app_sha256", "daemon_sha256")
_RECORD_FIELDS = ("phase", "operation", "target", "hardened_runtime", "entitlement_sha256", "outcome")
_REVIEW_FIELDS = ("owner", "owner_role", "reviewer", "reviewer_role", "review_id")

_CANDIDATE_NAME = re.compile(r"^[A-Za-z0-9._-]+\.app$")
_BUNDLE_ID = re.compile(r"^[A-Za-z0-9.-]+$")
_TEAM_IDENTIFIER = re.compile(r"^[A-Z0-9]{10}$")
_DESIGNATED_REQUIREMENT = re.compile(r"^designated => .+$")
_CDHASH = re.compile(r"^[0-9a-f]{40}$")
_MAIN_PATH = re.compile(r"^Contents/MacOS/[A-Za-z0-9._-]+$")
_COMMAND_TARGET = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
_REVIEW_TEXT = re.compile(r"^\S+$")
_OPERATIONS = ("sign", "verify", "metadata", "requirement", "entitlements", "submit", "staple", "validate", "assess")


class IngestionStatus(StrEnum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class IngestionResult:
    status: IngestionStatus
    failure: SigningFailure | None
    evidence_sha256: str | None


def ingest_production_evidence(payload, candidate: CandidateIdentity, expectation: SignatureExpectation, now: int) -> IngestionResult:
    """Validate production evidence and return a verified or rejected result."""
    try:
        return _ingest(payload, candidate, expectation, now)
    except Exception:
        return _rejected(FailureCode.EVIDENCE_INCOMPLETE, "ingest")


def _ingest(payload, candidate, expectation, now) -> IngestionResult:
    if scan_secrets(payload):
        return _rejected(FailureCode.EVIDENCE_SECRET_MARKER, "secret-scan")
    if isinstance(payload, dict) and payload.get("profile") == AD_HOC_PROFILE:
        return _rejected(FailureCode.PROFILE_DOWNGRADE_REJECTED, "downgrade")
    if isinstance(payload, dict) and (
        payload.get("environment_class") in SYNTHETIC_ENVIRONMENT_CLASSES
        or payload.get("schema_version") == SYNTHETIC_SCHEMA_VERSION
        or payload.get("kind") == SYNTHETIC_KIND
    ):
        return _rejected(FailureCode.SYNTHETIC_EVIDENCE_REJECTED, "synthetic")
    if not isinstance(candidate, CandidateIdentity) or not isinstance(expectation, SignatureExpectation) or not _conforms(payload):
        return _rejected(FailureCode.EVIDENCE_INCOMPLETE, "conformance")
    if payload["notarization"] != "accepted":
        return _rejected(FailureCode.NOTARIZATION_FAILED, "dispositions")
    if payload["stapling"] != "accepted":
        return _rejected(FailureCode.STAPLE_FAILED, "dispositions")
    if payload["gatekeeper"] != "accepted":
        return _rejected(FailureCode.GATEKEEPER_ASSESSMENT_FAILED, "dispositions")
    candidate_payload = payload["candidate"]
    if not _candidate_bound(candidate_payload, payload["entitlements"], payload["target"], candidate):
        return _rejected(FailureCode.ARTIFACT_IDENTITY_MISMATCH, "candidate-binding")
    if not _signature_bound(payload["signature"], expectation):
        return _rejected(FailureCode.ARTIFACT_IDENTITY_MISMATCH, "signature-binding")
    command_failure = _command_failure(payload["target"], payload["commands"], candidate)
    if command_failure is not None:
        return command_failure
    if not freshness_ok(payload["produced_at"], payload["fresh_until"], now):
        return _rejected(FailureCode.EVIDENCE_STALE, "freshness")
    if payload["review"]["owner"].casefold() == payload["review"]["reviewer"].casefold():
        return _rejected(FailureCode.EVIDENCE_INCOMPLETE, "review")
    if evidence_digest(payload) != payload["evidence_sha256"]:
        return _rejected(FailureCode.EVIDENCE_INTEGRITY, "integrity")
    return IngestionResult(IngestionStatus.VERIFIED, None, payload["evidence_sha256"])


def _rejected(code: FailureCode, phase: str) -> IngestionResult:
    return IngestionResult(IngestionStatus.REJECTED, SigningFailure(code, phase, ""), None)


def _conforms(payload) -> bool:
    if type(payload) is not dict or set(payload) != set(_TOP_LEVEL_FIELDS):
        return False
    if (
        payload["schema_version"] != SCHEMA_VERSION
        or payload["kind"] != KIND
        or payload["profile"] != PROFILE
        or payload["platform"] != PLATFORM
        or payload["environment_class"] != ENVIRONMENT_CLASS
        or payload["authenticity_method"] != AUTHENTICITY_METHOD
        or payload["producer_lane"] != PRODUCER_LANE
    ):
        return False
    if type(payload["produced_at"]) is not int or payload["produced_at"] < 0 or type(payload["fresh_until"]) is not int or payload["fresh_until"] < 0:
        return False
    if not _plain_disposition(payload["notarization"]) or not _plain_disposition(payload["stapling"]) or not _plain_disposition(payload["gatekeeper"]):
        return False
    if not _candidate_conforms(payload["candidate"]):
        return False
    if not _signature_conforms(payload["signature"]):
        return False
    if not _target_conforms(payload["target"]):
        return False
    entitlements = payload["entitlements"]
    if type(entitlements) is not dict or set(entitlements) != set(_ENTITLEMENTS_FIELDS) or not sha256_ok(entitlements["app_sha256"]) or not sha256_ok(entitlements["daemon_sha256"]):
        return False
    commands = payload["commands"]
    if type(commands) is not list or len(commands) != len(CANONICAL_PHASES):
        return False
    for index, record in enumerate(commands):
        if not _record_conforms(record, index):
            return False
    review = payload["review"]
    if type(review) is not dict or set(review) != set(_REVIEW_FIELDS):
        return False
    return all(type(review[field]) is str and _REVIEW_TEXT.fullmatch(review[field]) is not None and len(review[field]) <= 128 for field in _REVIEW_FIELDS)


def _candidate_conforms(value) -> bool:
    if type(value) is not dict or set(value) != set(_CANDIDATE_FIELDS) or _CANDIDATE_NAME.fullmatch(value["relative_name"]) is None:
        return False
    return all(sha256_ok(value[field]) for field in ("tree_sha256", "main_sha256", "daemon_sha256", "release_candidate_sha256", "app_entitlements_sha256", "daemon_entitlements_sha256"))


def _signature_conforms(value) -> bool:
    if type(value) is not dict or set(value) != set(_SIGNATURE_FIELDS):
        return False
    if _BUNDLE_ID.fullmatch(value["bundle_id"]) is None or _TEAM_IDENTIFIER.fullmatch(value["team_identifier"]) is None or value["authority_class"] != "Developer ID Application":
        return False
    if _DESIGNATED_REQUIREMENT.fullmatch(value["designated_requirement"]) is None or len(value["designated_requirement"]) > 512 or _CDHASH.fullmatch(value["cdhash"]) is None:
        return False
    return True


def _target_conforms(value) -> bool:
    if type(value) is not dict or set(value) != set(_TARGET_FIELDS) or _CANDIDATE_NAME.fullmatch(value["candidate"]) is None or _MAIN_PATH.fullmatch(value["main"]) is None:
        return False
    return value["daemon"] == "Contents/MacOS/runned"


def _record_conforms(record, index) -> bool:
    if type(record) is not dict or set(record) != set(_RECORD_FIELDS) or record["phase"] != CANONICAL_PHASES[index] or record["operation"] not in _OPERATIONS:
        return False
    if _COMMAND_TARGET.fullmatch(record["target"]) is None or type(record["hardened_runtime"]) is not bool:
        return False
    digest = record["entitlement_sha256"]
    return digest is None or sha256_ok(digest)


def _plain_disposition(value) -> bool:
    if type(value) is not str or not value or "/" in value:
        return False
    return all(ord(character) >= 32 and ord(character) != 127 for character in value)


def _candidate_bound(candidate_payload, entitlements, target_payload, candidate) -> bool:
    if (
        candidate_payload["relative_name"] != candidate.relative_name
        or candidate_payload["tree_sha256"] != candidate.tree_sha256
        or candidate_payload["main_sha256"] != candidate.main_sha256
        or candidate_payload["daemon_sha256"] != candidate.daemon_sha256
        or candidate_payload["release_candidate_sha256"] != candidate.release_candidate_sha256
        or candidate_payload["app_entitlements_sha256"] != candidate.app_entitlements_sha256
        or candidate_payload["daemon_entitlements_sha256"] != candidate.daemon_entitlements_sha256
    ):
        return False
    if entitlements["app_sha256"] != candidate.app_entitlements_sha256 or entitlements["daemon_sha256"] != candidate.daemon_entitlements_sha256:
        return False
    if target_payload["candidate"] != candidate.relative_name or target_payload["daemon"] != "Contents/MacOS/runned":
        return False
    main = target_payload["main"]
    return main.startswith("Contents/MacOS/") and main.rsplit("/", 1)[-1] != "runned"


def _signature_bound(signature_payload, expectation) -> bool:
    return (
        signature_payload["bundle_id"] == expectation.bundle_id
        and signature_payload["team_identifier"] == expectation.team_identifier
        and signature_payload["authority_class"] == expectation.authority_class
        and signature_payload["designated_requirement"] == expectation.designated_requirement
        and signature_payload["cdhash"] == expectation.cdhash
    )


def _command_failure(target_payload, commands, candidate) -> IngestionResult | None:
    target = EvidenceTarget(target_payload["candidate"], target_payload["main"], target_payload["daemon"])
    expected = expected_records(target, candidate)
    if len(commands) != len(expected):
        return _rejected(FailureCode.EVIDENCE_INCOMPLETE, "commands")
    for index, record in enumerate(commands):
        required = expected[index]
        if record["phase"] != required.phase or record["operation"] != required.operation:
            return _rejected(FailureCode.EVIDENCE_INCOMPLETE, "commands")
        if record["target"] != required.target:
            return _rejected(FailureCode.ARTIFACT_IDENTITY_MISMATCH, "commands")
        if record["hardened_runtime"] != required.hardened_runtime or record["entitlement_sha256"] != required.entitlement_sha256:
            return _rejected(FailureCode.SIGNATURE_INVALID, "commands")
        if record["outcome"] != "success":
            return _rejected(FailureCode.SIGNATURE_INVALID, "commands")
    return None
