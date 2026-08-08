"""Activation of signing claims from verified production evidence.

`activate_claim_from_evidence` — fused-функция: ингестирует production
evidence через `ingest_production_evidence` и, при подтверждении,
привязывает subject-дайджест к claim. Функция никогда не поднимает
исключений.

Инвариант конструирования: `ClaimActivation` создаётся только внутри
этого модуля; единственный публичный путь получения экземпляра —
`activate_claim_from_evidence`. Инварианты чистоты: модуль не читает
переменные окружения, не запускает внешние процессы, не выполняет
сетевых операций и не записывает файлы. Значения из payload в записи
активации не попадают (кроме явных дайджестов и claim id).
"""

import json
from dataclasses import dataclass
from enum import StrEnum

from .ingestion import IngestionStatus, ingest_production_evidence
from .ingestion_rules import sha256_ok
from .models import CandidateIdentity, SignatureExpectation

SIGNING_CLAIMS = ("macos_developer_id_signing", "notarization_stapling")


class ClaimTransition(StrEnum):
    ACTIVATED = "ACTIVATED"
    REMAINS_BLOCKED = "REMAINS_BLOCKED"


class ActivationReason(StrEnum):
    INGESTION_VERIFIED = "INGESTION_VERIFIED"
    INGESTION_NOT_VERIFIED = "INGESTION_NOT_VERIFIED"
    CANDIDATE_DIGEST_MISMATCH = "CANDIDATE_DIGEST_MISMATCH"
    UNKNOWN_CLAIM = "UNKNOWN_CLAIM"


@dataclass(frozen=True)
class ClaimActivation:
    claim_id: str
    transition: ClaimTransition
    reason: ActivationReason
    evidence_sha256: str | None
    candidate_digest: str
    subject_sha256: str


def activate_claim_from_evidence(
    claim_id: str, payload, candidate: CandidateIdentity, expectation: SignatureExpectation, now: int, subject_sha256: str
) -> ClaimActivation:
    """Activate a signing claim from verified evidence, never raising."""
    try:
        return _activate(claim_id, payload, candidate, expectation, now, subject_sha256)
    except Exception:
        return _activation(claim_id, ClaimTransition.REMAINS_BLOCKED, ActivationReason.INGESTION_NOT_VERIFIED, None, _candidate_digest(candidate), subject_sha256)


def _activate(claim_id, payload, candidate, expectation, now, subject_sha256) -> ClaimActivation:
    if claim_id not in SIGNING_CLAIMS:
        return _activation(claim_id, ClaimTransition.REMAINS_BLOCKED, ActivationReason.UNKNOWN_CLAIM, None, _candidate_digest(candidate), subject_sha256)
    if not _candidate_digest_ok(candidate) or not sha256_ok(subject_sha256):
        return _activation(claim_id, ClaimTransition.REMAINS_BLOCKED, ActivationReason.CANDIDATE_DIGEST_MISMATCH, None, _candidate_digest(candidate), subject_sha256)
    result = ingest_production_evidence(payload, candidate, expectation, now)
    if result.status is not IngestionStatus.VERIFIED:
        return _activation(claim_id, ClaimTransition.REMAINS_BLOCKED, ActivationReason.INGESTION_NOT_VERIFIED, None, _candidate_digest(candidate), subject_sha256)
    if candidate.release_candidate_sha256 != subject_sha256:
        return _activation(claim_id, ClaimTransition.REMAINS_BLOCKED, ActivationReason.CANDIDATE_DIGEST_MISMATCH, None, _candidate_digest(candidate), subject_sha256)
    return _activation(claim_id, ClaimTransition.ACTIVATED, ActivationReason.INGESTION_VERIFIED, result.evidence_sha256, _candidate_digest(candidate), subject_sha256)


def _candidate_digest(candidate) -> str:
    return candidate.release_candidate_sha256 if _candidate_digest_ok(candidate) else ""


def _candidate_digest_ok(candidate) -> bool:
    return isinstance(candidate, CandidateIdentity) and sha256_ok(candidate.release_candidate_sha256)


def _activation(claim_id, transition, reason, evidence_sha256, candidate_digest, subject_sha256) -> ClaimActivation:
    return ClaimActivation(claim_id, transition, reason, evidence_sha256, candidate_digest, subject_sha256)


def normalize_claim_activation(activation: ClaimActivation) -> bytes:
    """Serialize an activation record as compact sorted JSON with a trailing newline."""
    payload = {
        "candidate_digest": activation.candidate_digest,
        "claim_id": activation.claim_id,
        "evidence_sha256": activation.evidence_sha256,
        "reason": activation.reason.value,
        "subject_sha256": activation.subject_sha256,
        "transition": activation.transition.value,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
