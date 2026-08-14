"""Authenticated profile projections for fixture-only profile semantics tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from scripts.rc0_policy.external_envelope import PrincipalBinding
from scripts.rc0_policy.platform_attestation_profiles import AuthenticatedProfileEvidence
from scripts.rc0_policy.platform_policy_report import verify_qualified_declaration
from scripts.tests.rc0_platform_policy_support import valid_declaration_fixture


@dataclass(frozen=True)
class ProfileFixture:
    mapping: object
    report: object
    profiles: tuple[AuthenticatedProfileEvidence, ...]
    canaries: tuple[AuthenticatedProfileEvidence, ...]


def valid_profile_fixture(scope_id: str) -> ProfileFixture:
    fixture = valid_declaration_fixture()
    declaration = verify_qualified_declaration(
        fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver,
        fixture.verify_envelope, fixture.now_epoch_seconds,
    )
    slots = tuple(sorted(row.artifact_slot_id for row in fixture.mapping.artifact_slots if row.platform_scope_id == scope_id))
    gates = tuple(sorted(hashlib.sha256(b"gocode.rc0.profile-gate-evidence-row/1\0" + row.canonical_row_bytes).hexdigest() for row in declaration.report.required_gate_results))
    native = PrincipalBinding("native_host_attestor", "native-subject", "native-account", "native-session", "native-lane")
    canary = PrincipalBinding("external_canary_operator", "canary-subject", "canary-account", "canary-session", "canary-lane")
    profiles, canaries = [], []
    results = {"required": "PASS", "external_canary_only": "PASS", "disabled_by_policy": "DISABLED_BY_POLICY", "backend_unavailable": "BackendUnavailable"}
    for index, row in enumerate(item for item in fixture.mapping.profile_states if item.platform_scope_id == scope_id):
        payload = {"platform_scope_id": scope_id, "profile_id": row.profile_id, "profile_revision": row.profile_revision, "profile_sha256": row.profile_sha256, "state": row.state, "canonical_result": results[row.state], "artifact_slot_ids": list(slots), "rc0_gate_evidence_sha256s": list(gates)}
        target, identity = (canaries, canary) if row.state == "external_canary_only" else (profiles, native)
        if target is canaries: payload["operator_lane_id"] = canary.lane_id
        target.append(AuthenticatedProfileEvidence(payload, f"{index:064x}", identity))
    return ProfileFixture(fixture.mapping, declaration.report, tuple(profiles), tuple(canaries))
