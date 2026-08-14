"""Fixture-only platform-qualified subject contract."""
from __future__ import annotations

import inspect
import unittest
from dataclasses import replace
from itertools import combinations
from unittest.mock import patch

from scripts.rc0_policy.qualified_subject import SubjectFailure, fixture_collect_authority_roles, fixture_verify_qualified_subject
from scripts.rc0_policy.platform_attestation import PlatformAttestationView
from scripts.tests.rc0_platform_subject_support import replace_subject_field, valid_subject_fixture


class QualifiedSubjectContractTests(unittest.TestCase):
    def test_exposes_the_frozen_subject_entrypoints(self) -> None:
        from scripts.rc0_policy.qualified_subject import (
            QualifiedSubjectView, fixture_collect_authority_roles, fixture_verify_qualified_subject,
        )

        self.assertEqual(
            tuple(QualifiedSubjectView.__dataclass_fields__),
            (
                "envelope_sha256", "repository_id", "issuer_identity",
                "rc0_qualified_declaration_envelope_sha256",
                "rc0_verification_report_envelope_sha256",
                "common_binding_group_payload_sha256",
                "rc0_qualification_policy_digest", "mapping_policy_envelope_sha256",
                "active_activation_snapshot_envelope_sha256",
                "normalized_mapping_payload_sha256", "attestation_envelope_sha256s",
                "required_gate_set_payload_sha256", "profile_state_set_payload_sha256",
                "artifact_set_payload_sha256", "_subject_envelope", "_declaration",
                "_report", "_mapping", "_activation", "_attestations",
                "_canonical_source_bytes", "_verification_token",
            ),
        )
        self.assertEqual(
            tuple(inspect.signature(fixture_verify_qualified_subject).parameters),
            ("subject", "declaration", "report", "mapping", "activation", "attestations", "now_epoch_seconds"),
        )
        self.assertEqual(tuple(inspect.signature(fixture_collect_authority_roles).parameters), tuple(inspect.signature(fixture_verify_qualified_subject).parameters))

    def test_subject_equals_the_verified_declaration_and_three_attestations(self) -> None:
        fixture = valid_subject_fixture()
        view = fixture_verify_qualified_subject(
            fixture.subject, fixture.declaration, fixture.report, fixture.mapping,
            fixture.activation, fixture.attestations, fixture.now_epoch_seconds,
        )
        self.assertEqual(view.rc0_qualified_declaration_envelope_sha256, fixture.declaration.envelope_sha256)
        self.assertEqual(view.rc0_verification_report_envelope_sha256, fixture.report.envelope_sha256)
        self.assertEqual(view.attestation_envelope_sha256s, tuple(sorted(item.envelope_sha256 for item in fixture.attestations)))
        view.require_verified(fixture.now_epoch_seconds)

    def test_rejects_aggregator_substitution_of_a_duplicated_binding(self) -> None:
        fixture = valid_subject_fixture()
        for field in (
            "common_binding_group_payload_sha256", "rc0_qualification_policy_digest",
            "rc0_verification_report_envelope_sha256", "required_gate_set_payload_sha256",
            "artifact_set_payload_sha256",
        ):
            with self.subTest(field=field), self.assertRaises(SubjectFailure):
                fixture_verify_qualified_subject(
                    replace_subject_field(fixture.subject, field, "d" * 64),
                    fixture.declaration, fixture.report, fixture.mapping, fixture.activation,
                    fixture.attestations, fixture.now_epoch_seconds,
                )

    def test_rejects_post_issuance_attestation_container_replacement(self) -> None:
        fixture = valid_subject_fixture()
        view = fixture_verify_qualified_subject(
            fixture.subject, fixture.declaration, fixture.report, fixture.mapping,
            fixture.activation, fixture.attestations, fixture.now_epoch_seconds,
        )
        object.__setattr__(view, "_attestations", tuple(reversed(view._attestations)))
        with self.assertRaisesRegex(SubjectFailure, "SUBJECT_VERIFIED_INVALID"):
            view.require_verified(fixture.now_epoch_seconds)

    def test_attestation_requires_the_exact_minted_predecessor_graph(self) -> None:
        fixture = valid_subject_fixture()
        alternate = valid_subject_fixture()
        fixture.attestations[0].require_dependencies(
            fixture.mapping, fixture.mapping.adjunct_trust, fixture.activation,
            fixture.declaration, fixture.report, fixture.now_epoch_seconds,
        )
        with self.assertRaises(Exception):
            fixture.attestations[0].require_dependencies(
                alternate.mapping, alternate.mapping.adjunct_trust,
                alternate.activation, alternate.declaration, alternate.report,
                fixture.now_epoch_seconds,
            )

    def test_valid_alternate_lineage_remains_self_consistent(self) -> None:
        fixture = valid_subject_fixture()
        fixture_verify_qualified_subject(
            fixture.subject, fixture.declaration, fixture.report, fixture.mapping,
            fixture.activation, fixture.attestations, fixture.now_epoch_seconds,
        ).require_verified(fixture.now_epoch_seconds)

    def test_subject_replay_rejects_an_equal_looking_public_replacement(self) -> None:
        class AlwaysEqual:
            def __eq__(self, other: object) -> bool: return True
        fixture = valid_subject_fixture()
        view = fixture_verify_qualified_subject(
            fixture.subject, fixture.declaration, fixture.report, fixture.mapping,
            fixture.activation, fixture.attestations, fixture.now_epoch_seconds,
        )
        object.__setattr__(view, "attestation_envelope_sha256s", AlwaysEqual())
        with self.assertRaises(SubjectFailure):
            view.require_verified(fixture.now_epoch_seconds)

    def test_subject_replay_requires_minted_public_and_source_identities(self) -> None:
        fixture = valid_subject_fixture()
        view = fixture_verify_qualified_subject(
            fixture.subject, fixture.declaration, fixture.report, fixture.mapping,
            fixture.activation, fixture.attestations, fixture.now_epoch_seconds,
        )
        object.__setattr__(view, "issuer_identity", replace(view.issuer_identity))
        with self.assertRaises(SubjectFailure): view.require_verified(fixture.now_epoch_seconds)
        view = fixture_verify_qualified_subject(
            fixture.subject, fixture.declaration, fixture.report, fixture.mapping,
            fixture.activation, fixture.attestations, fixture.now_epoch_seconds,
        )
        object.__setattr__(view, "_canonical_source_bytes", bytes(bytearray(view._canonical_source_bytes)))
        with self.assertRaises(SubjectFailure): view.require_verified(fixture.now_epoch_seconds)

    def test_subject_view_weak_state_does_not_retain_view(self) -> None:
        import gc, weakref
        fixture = valid_subject_fixture()
        view = fixture_verify_qualified_subject(fixture.subject, fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, fixture.now_epoch_seconds)
        reference = weakref.ref(view); del view; gc.collect()
        self.assertIsNone(reference())

    def test_subject_rejects_nonexact_digests_and_raw_record_substitutes(self) -> None:
        fixture = valid_subject_fixture()
        with self.assertRaises(SubjectFailure):
            fixture_verify_qualified_subject(replace_subject_field(fixture.subject, "platform_attestation_envelope_sha256s", ["d" * 64, "e" * 64, "f" * 64]), fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, fixture.now_epoch_seconds)
        import scripts.rc0_policy.platform_attestation as attestation
        raw_manifest = attestation._VIEWS[fixture.attestations[0]].inputs[1].classifier_pairs[0][0]
        for raw in (raw_manifest, fixture.declaration, fixture.report):
            with self.subTest(raw=type(raw).__name__), self.assertRaises(SubjectFailure):
                fixture_verify_qualified_subject(raw, fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, fixture.now_epoch_seconds)

    def test_subject_replay_rejects_attestation_omission_or_substitution(self) -> None:
        fixture = valid_subject_fixture()
        view = fixture_verify_qualified_subject(fixture.subject, fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, fixture.now_epoch_seconds)
        object.__setattr__(view, "_attestations", view._attestations[:2])
        with self.assertRaises(SubjectFailure): view.require_verified(fixture.now_epoch_seconds)
        alternate = valid_subject_fixture()
        view = fixture_verify_qualified_subject(fixture.subject, fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, fixture.now_epoch_seconds)
        object.__setattr__(view, "_attestations", (alternate.attestations[0], *view._attestations[1:]))
        with self.assertRaises(SubjectFailure): view.require_verified(fixture.now_epoch_seconds)

    def test_subject_calls_attestation_verification_before_field_access(self) -> None:
        fixture = valid_subject_fixture()
        with patch.object(PlatformAttestationView, "require_verified", side_effect=ValueError("ORDER")) as check:
            with self.assertRaises(SubjectFailure):
                fixture_verify_qualified_subject(fixture.subject, fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, fixture.now_epoch_seconds)
        check.assert_called_once_with(fixture.now_epoch_seconds)

    def test_subject_final_artifact_join_rejects_self_consistent_report_vectors(self) -> None:
        base = valid_subject_fixture(); rows = [{"relative_path": row.relative_path, "sha256": row.sha256, "size": row.size, "locator": row.locator} for row in base.report.artifact_bindings]
        vectors = (rows[:-1], rows + [{"relative_path":"dist/zz","sha256":"f" * 64,"size":10,"locator":"cas:sha256:" + "f" * 64}], [*rows[:-1], {**rows[-1], "relative_path":"dist/zz", "sha256":"e" * 64, "locator":"cas:sha256:" + "e" * 64}])
        import scripts.rc0_policy.qualified_subject as subject_module
        for changed in vectors:
            fixture = valid_subject_fixture(artifact_rows=changed)
            with patch.object(subject_module, "_artifacts", wraps=subject_module._artifacts) as check, self.assertRaisesRegex(SubjectFailure, "ARTIFACT_SET_MISMATCH"):
                fixture_verify_qualified_subject(fixture.subject, fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, fixture.now_epoch_seconds)
            check.assert_called_once()

    def test_subject_final_join_rejects_valid_principal_outside_adjunct_registry(self) -> None:
        foreign = {"subject_id":"outside-adjunct-trust","controlling_account_id":"outside-account","delegated_session_id":"outside-session","lane_id":"outside-lane"}
        fixture = valid_subject_fixture(subject_principal=foreign)
        import scripts.rc0_policy.qualified_subject as subject_module
        with patch.object(subject_module, "_roles", wraps=subject_module._roles) as check, self.assertRaisesRegex(SubjectFailure, "SUBJECT_ENVELOPE_INVALID"):
            fixture_verify_qualified_subject(fixture.subject, fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, fixture.now_epoch_seconds)
        check.assert_called_once()

    def test_subject_closure_uses_the_report_utf8_primitive_order_for_ten_and_two(self) -> None:
        fixture = valid_subject_fixture()
        fixture_verify_qualified_subject(fixture.subject, fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, fixture.now_epoch_seconds).require_verified(fixture.now_epoch_seconds)
        from scripts.rc0_policy.qualified_subject import _artifact_order_key
        rows = [("dist/agent", "a" * 64, size, "cas:sha256:" + "a" * 64) for size in (2, 10)]
        self.assertEqual([row[2] for row in sorted(rows, key=_artifact_order_key)], [10, 2])

    def test_subject_accepts_full_signed_closure_with_real_ten_and_two_sizes(self) -> None:
        base = valid_subject_fixture(); rows = [{"relative_path": row.relative_path, "sha256": row.sha256, "size": row.size, "locator": row.locator} for row in base.report.artifact_bindings]
        rows[0]["size"], rows[1]["size"] = 10, 2
        fixture = valid_subject_fixture(artifact_rows=rows, match_artifacts=True)
        self.assertEqual([fixture.report.artifact_bindings[index].size for index in (0, 1)], [10, 2])
        fixture_verify_qualified_subject(fixture.subject, fixture.declaration, fixture.report, fixture.mapping, fixture.activation, fixture.attestations, fixture.now_epoch_seconds).require_verified(fixture.now_epoch_seconds)

    def test_collects_the_exact_fourteen_disjoint_registry_roles(self) -> None:
        fixture = valid_subject_fixture()
        rows = fixture_collect_authority_roles(
            fixture.subject, fixture.declaration, fixture.report, fixture.mapping,
            fixture.activation, fixture.attestations, fixture.now_epoch_seconds,
        )
        self.assertEqual(len(rows), 14)
        self.assertEqual(tuple(row.role_id for row in rows), tuple(sorted(row.role_id for row in rows)))
        for first, second in combinations(rows, 2):
            for dimension in ("subject_id", "controlling_account_id", "delegated_session_id", "lane_id"):
                with self.subTest(first=first.role_id, second=second.role_id, dimension=dimension):
                    self.assertNotEqual(
                        getattr(first.principals[0], dimension),
                        getattr(second.principals[0], dimension),
                    )
