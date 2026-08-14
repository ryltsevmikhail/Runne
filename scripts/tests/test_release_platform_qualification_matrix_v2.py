"""Canonical platform qualification matrix projection tests."""

from __future__ import annotations

import hashlib
import unittest
from unittest.mock import patch

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy.platform_attestation import verify_platform_attestation
from scripts.rc0_policy.platform_matrix import MatrixFailure, VerifiedMatrixView, normalized_platform_mapping_payload, fixture_verify_platform_matrix
from scripts.rc0_policy.qualified_subject import QualifiedSubjectView, SubjectFailure
from scripts.tests.rc0_platform_attestation_trust_support import valid_attestation_fixture
from scripts.tests.rc0_platform_subject_support import valid_matrix_fixture


SCOPES = (
    "linux-ubuntu-24_04-x86_64-production",
    "windows-11-24h2-x86_64-production",
    "macos-14-arm64-development-preview",
)


def _views() -> tuple[object, object, object]:
    return tuple(verify_platform_attestation(**valid_attestation_fixture(scope).arguments()) for scope in SCOPES)


class MatrixTests(unittest.TestCase):
    def test_mapping_sorts_cells_profiles_artifacts_and_evidence(self) -> None:
        views = _views()
        mapping = loads_canonical(normalized_platform_mapping_payload(tuple(reversed(views))))
        self.assertEqual([cell["platform_scope_id"] for cell in mapping["cells"]], sorted(SCOPES))
        for cell in mapping["cells"]:
            self.assertEqual([row["profile_id"] for row in cell["profile_rows"]], sorted(row["profile_id"] for row in cell["profile_rows"]))
            self.assertEqual([row["artifact_slot_id"] for row in cell["artifact_rows"]], sorted(row["artifact_slot_id"] for row in cell["artifact_rows"]))
            self.assertEqual(cell["evidence_envelope_sha256s"], sorted(cell["evidence_envelope_sha256s"]))

    def test_every_cell_semantic_changes_mapping_digest(self) -> None:
        mapping = loads_canonical(normalized_platform_mapping_payload(_views()))
        original = hashlib.sha256(canonical_bytes(mapping)).hexdigest()
        cell = mapping["cells"][0]
        fields = ("platform_scope_id", "qualification_class", "support_disposition", "os_family", "os_version", "os_build", "kernel_or_image_sha256", "architecture", "native_mode")
        for field in fields:
            changed = loads_canonical(canonical_bytes(mapping))
            changed["cells"][0][field] = "changed" if field != "platform_scope_id" else "other-scope"
            with self.subTest(field=field):
                self.assertNotEqual(original, hashlib.sha256(canonical_bytes(changed)).hexdigest())
        for rows, field, replacement in (
            ("profile_rows", "profile_id", "changed"),
            ("profile_rows", "profile_revision", "changed"),
            ("profile_rows", "profile_sha256", "f" * 64),
            ("profile_rows", "state", "changed"),
            ("profile_rows", "evidence_envelope_sha256", "f" * 64),
            ("artifact_rows", "artifact_slot_id", "changed"),
            ("artifact_rows", "relative_path", "changed"),
            ("artifact_rows", "sha256", "f" * 64),
            ("artifact_rows", "size", 123456),
            ("artifact_rows", "locator", "cas:sha256:" + "f" * 64),
            ("artifact_rows", "artifact_manifest_payload_sha256", "f" * 64),
            ("artifact_rows", "product_manifest_payload_sha256", "f" * 64),
            ("evidence_envelope_sha256s", None, "f" * 64),
        ):
            changed = loads_canonical(canonical_bytes(mapping))
            if field is None:
                changed["cells"][0][rows][0] = replacement
            else:
                changed["cells"][0][rows][0][field] = replacement
            with self.subTest(rows=rows, field=field):
                self.assertNotEqual(original, hashlib.sha256(canonical_bytes(changed)).hexdigest())

    def test_requires_exact_three_unique_verified_scope_views(self) -> None:
        linux, windows, macos = _views()
        with self.assertRaises(MatrixFailure):
            normalized_platform_mapping_payload((linux, windows))
        with self.assertRaises(MatrixFailure):
            normalized_platform_mapping_payload((linux, linux, macos))

    def test_mapping_replays_predecessor_owned_attestation_integrity(self) -> None:
        views = _views()
        import scripts.rc0_policy.platform_attestation as attestation_module
        mapping = attestation_module._VIEWS[views[0]].inputs[2]
        object.__setattr__(mapping, "_canonical_source_bytes", b"forged")
        with self.assertRaises(MatrixFailure):
            normalized_platform_mapping_payload(views)

    def test_matrix_recomputes_subject_mapping_digest(self) -> None:
        fixture = valid_matrix_fixture()
        view = fixture_verify_platform_matrix(fixture.matrix, fixture.subject, fixture.now_epoch_seconds)
        self.assertEqual(view.normalized_platform_mapping_payload_bytes, canonical_bytes(fixture.mapping))
        self.assertEqual(view.normalized_platform_mapping_payload_sha256, hashlib.sha256(canonical_bytes(fixture.mapping)).hexdigest())
        payload = loads_canonical(fixture.matrix.payload_canonical_bytes)
        payload["normalized_platform_mapping_payload_sha256"] = "d" * 64
        from scripts.tests.rc0_platform_attestation_trust_support import envelope
        with self.assertRaises(MatrixFailure):
            fixture_verify_platform_matrix(envelope(payload, "gocode.release.platform-qualification-matrix/2", "qualification_aggregator"), fixture.subject, fixture.now_epoch_seconds)

    def test_subject_matrix_graph_has_no_reverse_digest_edge(self) -> None:
        self.assertNotIn("matrix", QualifiedSubjectView.__dataclass_fields__)
        self.assertNotIn("platform_matrix", QualifiedSubjectView.__dataclass_fields__)

    def test_preview_evidence_cannot_close_production_cell(self) -> None:
        fixture = valid_matrix_fixture()
        changed = loads_canonical(canonical_bytes(fixture.mapping))
        preview = next(cell for cell in changed["cells"] if cell["platform_scope_id"] == "macos-14-arm64-development-preview")
        preview["qualification_class"] = "production"
        preview["support_disposition"] = "supported"
        payload = loads_canonical(fixture.matrix.payload_canonical_bytes)
        payload["normalized_platform_mapping"] = changed
        payload["normalized_platform_mapping_payload_sha256"] = hashlib.sha256(canonical_bytes(changed)).hexdigest()
        from scripts.tests.rc0_platform_attestation_trust_support import envelope
        with self.assertRaises(MatrixFailure):
            fixture_verify_platform_matrix(envelope(payload, "gocode.release.platform-qualification-matrix/2", "qualification_aggregator"), fixture.subject, fixture.now_epoch_seconds)

    def test_unknown_matrix_version_fails_closed(self) -> None:
        fixture = valid_matrix_fixture()
        object.__setattr__(fixture.matrix, "payload_schema_id", "gocode.release.platform-qualification-matrix/3")
        with self.assertRaises(MatrixFailure):
            fixture_verify_platform_matrix(fixture.matrix, fixture.subject, fixture.now_epoch_seconds)

    def test_matrix_view_is_opaque_replays_and_calls_subject_first(self) -> None:
        fixture = valid_matrix_fixture()
        view = fixture_verify_platform_matrix(fixture.matrix, fixture.subject, fixture.now_epoch_seconds)
        self.assertFalse(hasattr(view, "__dict__"))
        with self.assertRaises(TypeError):
            VerifiedMatrixView(object())
        object.__setattr__(view, "_canonical_source_bytes", b"forged")
        with self.assertRaises(MatrixFailure):
            view.require_verified(fixture.now_epoch_seconds)
        view = fixture_verify_platform_matrix(fixture.matrix, fixture.subject, fixture.now_epoch_seconds)
        with patch.object(QualifiedSubjectView, "require_verified", side_effect=SubjectFailure("ORDER")) as check:
            with self.assertRaises(MatrixFailure):
                view.require_verified(fixture.now_epoch_seconds)
        check.assert_called_once_with(fixture.now_epoch_seconds)

    def test_matrix_replay_requires_minted_byte_identities(self) -> None:
        fixture = valid_matrix_fixture()
        view = fixture_verify_platform_matrix(fixture.matrix, fixture.subject, fixture.now_epoch_seconds)
        object.__setattr__(view, "normalized_platform_mapping_payload_bytes", bytes(bytearray(view.normalized_platform_mapping_payload_bytes)))
        with self.assertRaises(MatrixFailure): view.require_verified(fixture.now_epoch_seconds)
        view = fixture_verify_platform_matrix(fixture.matrix, fixture.subject, fixture.now_epoch_seconds)
        object.__setattr__(view, "_canonical_source_bytes", bytes(bytearray(view._canonical_source_bytes)))
        with self.assertRaises(MatrixFailure): view.require_verified(fixture.now_epoch_seconds)

    def test_matrix_view_weak_state_does_not_retain_view(self) -> None:
        import gc, weakref
        fixture = valid_matrix_fixture()
        view = fixture_verify_platform_matrix(fixture.matrix, fixture.subject, fixture.now_epoch_seconds)
        reference = weakref.ref(view); del view; gc.collect()
        self.assertIsNone(reference())

    def test_rejects_private_subject_dependency_substitution(self) -> None:
        fixture = valid_matrix_fixture()
        object.__setattr__(fixture.subject, "_mapping", object())
        with self.assertRaises(MatrixFailure):
            fixture_verify_platform_matrix(fixture.matrix, fixture.subject, fixture.now_epoch_seconds)


if __name__ == "__main__":
    unittest.main()
