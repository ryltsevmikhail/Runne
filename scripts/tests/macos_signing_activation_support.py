"""Synthetic fixtures for macOS production signing activation tests.

Все данные — SYNTHETIC: дайджесты детерминированы и построены из
labels, никаких real-looking secrets. Документы строятся по канонической
схеме и каноническим фазам исполнения (см. `execution.expected_records`).
"""

import hashlib

from scripts.macos_signing.ingestion_rules import CANONICAL_PHASES, PHASE_OPERATIONS, SIGN_PHASES, evidence_digest
from scripts.macos_signing.models import CandidateIdentity, SignatureExpectation

NOW = 1_700_000_000
PRODUCED_AT = NOW - 3600
FRESH_UNTIL = NOW + 3600


def synthetic_identity() -> CandidateIdentity:
    """Return a deterministic synthetic candidate identity."""
    return CandidateIdentity(
        relative_name="synthetic-Runne.app",
        tree_sha256=hashlib.sha256(b"tree").hexdigest(),
        main_sha256=hashlib.sha256(b"main").hexdigest(),
        daemon_sha256=hashlib.sha256(b"daemon").hexdigest(),
        release_candidate_sha256=hashlib.sha256(b"release-candidate").hexdigest(),
        app_entitlements_sha256=hashlib.sha256(b"app-entitlements").hexdigest(),
        daemon_entitlements_sha256=hashlib.sha256(b"daemon-entitlements").hexdigest(),
    )


def synthetic_expectation() -> SignatureExpectation:
    """Return a deterministic synthetic signature expectation."""
    return SignatureExpectation(
        bundle_id="com.example.runne",
        team_identifier="TEAM000001",
        authority_class="Developer ID Application",
        designated_requirement="designated => identifier com.example.runne",
        cdhash="c" * 40,
    )


def _command_specs(identity: CandidateIdentity) -> list[dict]:
    return [
        {
            "phase": phase,
            "operation": PHASE_OPERATIONS[phase],
            "target": _expected_target(phase, identity),
            "hardened_runtime": phase in SIGN_PHASES,
            "entitlement_sha256": identity.daemon_entitlements_sha256 if phase == "sign-daemon" else identity.app_entitlements_sha256 if phase == "sign-app" else None,
            "outcome": "success",
        }
        for phase in CANONICAL_PHASES
    ]


def _expected_target(phase: str, identity: CandidateIdentity) -> str:
    if phase.startswith(("sign-", "verify-", "metadata-", "requirement-", "entitlements-")):
        return f"{identity.relative_name}/Contents/MacOS/runned" if phase.endswith("-daemon") else identity.relative_name
    return identity.relative_name


def synthetic_document(identity: CandidateIdentity | None = None, expectation: SignatureExpectation | None = None) -> dict:
    """Return a full valid synthetic production evidence document."""
    identity = identity if identity is not None else synthetic_identity()
    expectation = expectation if expectation is not None else synthetic_expectation()
    document = {
        "schema_version": "macos-production-evidence.v1",
        "kind": "macos-production-signing",
        "profile": "production-developer-id",
        "platform": "darwin",
        "environment_class": "PRODUCTION",
        "authenticity_method": "HUMAN_OPERATOR",
        "producer_lane": "macos-human-operator",
        "candidate": {
            "relative_name": identity.relative_name,
            "tree_sha256": identity.tree_sha256,
            "main_sha256": identity.main_sha256,
            "daemon_sha256": identity.daemon_sha256,
            "release_candidate_sha256": identity.release_candidate_sha256,
            "app_entitlements_sha256": identity.app_entitlements_sha256,
            "daemon_entitlements_sha256": identity.daemon_entitlements_sha256,
        },
        "signature": {
            "bundle_id": expectation.bundle_id,
            "team_identifier": expectation.team_identifier,
            "authority_class": expectation.authority_class,
            "designated_requirement": expectation.designated_requirement,
            "cdhash": expectation.cdhash,
        },
        "target": {"candidate": identity.relative_name, "main": "Contents/MacOS/Runne", "daemon": "Contents/MacOS/runned"},
        "entitlements": {"app_sha256": identity.app_entitlements_sha256, "daemon_sha256": identity.daemon_entitlements_sha256},
        "commands": _command_specs(identity),
        "notarization": "accepted",
        "stapling": "accepted",
        "gatekeeper": "accepted",
        "produced_at": PRODUCED_AT,
        "fresh_until": FRESH_UNTIL,
        "review": {
            "owner": "release-owner",
            "owner_role": "release-owner",
            "reviewer": "release-reviewer",
            "reviewer_role": "security-review",
            "review_id": "REVIEW-2026-08-06-0001",
        },
    }
    return finalized(document)


def finalized(document: dict) -> dict:
    """Return a copy of the document with a recalculated canonical digest."""
    return {**document, "evidence_sha256": evidence_digest(document)}


def without(document: dict, key: str) -> dict:
    """Return a copy of the document without one top-level key (digest untouched)."""
    result = dict(document)
    del result[key]
    return result


def with_changed(document: dict, path: tuple[str, ...], value) -> dict:
    """Return a copy of the document with one nested value replaced (digest untouched)."""
    result = dict(document)
    node = result
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return result
