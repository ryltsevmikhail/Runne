import hashlib
import json
import unittest
from dataclasses import asdict, replace
from pathlib import Path

from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.model import (
    ArtifactEntry,
    ArtifactInventoryV2,
    BuildInputIdentityV2,
    FailureCodeV1,
    ProductTupleIdentityV1,
    QualificationSubjectIdentityV1,
    ReleaseFailure,
)
from scripts.tests.release_v2_support import dependency_inventory


class ManifestTests(unittest.TestCase):
    def test_unverified_fixture_gate_has_no_structural_validity_status(self) -> None:
        from scripts.release_v2.gate import evaluate_gate
        from scripts.release_v2.manifest import assemble_manifest

        manifest = assemble_manifest(_input())
        self.assertEqual(manifest.candidate.manifest_schema, "release-manifest.v2")
        self.assertEqual(manifest.product_components, manifest.inventory.entries)
        result = evaluate_gate(manifest, context=None, fixture_mode=True)
        self.assertEqual(
            (result.fixture_status, result.overall_status.value, result.production_approved),
            (None, "BLOCKED_EVIDENCE", False),
        )
        self.assertNotIn("fixture_status", result.as_dict())

    def test_advisory_digest_mismatch_blocks_before_manifest_assembly(self) -> None:
        from scripts.release_v2.manifest import ManifestInputsV2, assemble_manifest

        values = _input()
        mismatch = replace(values.binding, advisory_report_sha256="0" * 64)
        altered = replace(values, binding=mismatch)
        with self.assertRaises(ReleaseFailure) as raised:
            assemble_manifest(altered)
        self.assertIs(raised.exception.code, FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_evidence_binding_inventory_mismatch_blocks_before_manifest_assembly(self) -> None:
        from scripts.release_v2.manifest import assemble_manifest

        values = _input()
        altered = replace(values, binding=replace(values.binding, artifact_inventory_sha256="0" * 64))
        with self.assertRaises(ReleaseFailure) as raised:
            assemble_manifest(altered)
        self.assertIs(raised.exception.code, FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_v1_manifest_cannot_masquerade_as_v2(self) -> None:
        from scripts.release_v2.manifest import parse_manifest

        with self.assertRaises(ReleaseFailure) as raised:
            parse_manifest(b'{"schema_version":"release-manifest.v1"}\n')
        self.assertIs(raised.exception.code, FailureCodeV1.MANIFEST_INVALID)

    def test_release_profile_must_be_exact_release_in_assembly_and_parse(self) -> None:
        from scripts.release_v2.manifest import assemble_manifest, manifest_bytes, parse_manifest

        inputs = _input()
        document = json.loads(manifest_bytes(assemble_manifest(inputs)))
        for profile in ("debug", "unknown"):
            with self.subTest(profile=profile):
                with self.assertRaises(ReleaseFailure) as raised:
                    assemble_manifest(replace(inputs, build=replace(inputs.build, release_profile=profile)))
                self.assertIs(raised.exception.code, FailureCodeV1.MANIFEST_INVALID)

                parsed = dict(document)
                parsed["release_profile"] = profile
                candidate = {key: parsed[key] for key in ("artifact_inventory_sha256", "build_input_sha256", "manifest_schema", "product_tuple_sha256", "qualification_evidence_sha256s", "release_profile")}
                parsed["candidate_sha256"] = hashlib.sha256(canonical_json(candidate)).hexdigest()
                with self.assertRaises(ReleaseFailure) as raised:
                    parse_manifest(canonical_json(parsed))
                self.assertIs(raised.exception.code, FailureCodeV1.MANIFEST_INVALID)

    def test_parsed_manifest_recomputes_candidate_preimage_and_evidence_order(self) -> None:
        from scripts.release_v2.manifest import assemble_manifest, manifest_bytes, parse_manifest

        value = json.loads(manifest_bytes(assemble_manifest(_input())))
        cases = (
            {**value, "candidate_sha256": "0" * 64},
            {**value, "qualification_evidence_sha256s": list(reversed(value["qualification_evidence_sha256s"]))},
            {**value, "qualification_evidence_sha256s": [value["qualification_evidence_sha256s"][0]] * len(value["qualification_evidence_sha256s"])},
            {**value, "qualification_evidence_sha256s": ["0" * 64, *value["qualification_evidence_sha256s"][1:]]},
        )
        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(ReleaseFailure) as raised:
                    parse_manifest(canonical_json(document))
                self.assertIs(raised.exception.code, FailureCodeV1.MANIFEST_INVALID)

    def test_gate_collects_sorted_closed_failures_for_invalid_candidate(self) -> None:
        from scripts.release_v2.gate import evaluate_gate
        from scripts.release_v2.manifest import assemble_manifest

        manifest = assemble_manifest(_input())
        result = evaluate_gate(replace(manifest, candidate=replace(manifest.candidate, release_profile="debug")), context=None, fixture_mode=True)
        self.assertFalse(result.production_approved)
        self.assertIsNone(result.fixture_status)
        self.assertEqual(result.production_gate.failure_code, FailureCodeV1.PRODUCTION_GATE_BLOCKED)
        self.assertEqual(tuple(sorted(result.failures, key=lambda item: (item.code.value, item.detail))), result.failures)

    def test_schemas_are_closed_draft_2020_12_documents(self) -> None:
        schemas = (
            "release-manifest-v2.schema.json",
            "release-evidence-v1.schema.json",
            "release-archive-index-v1.schema.json",
            "release-claim-matrix-v1.schema.json",
        )
        root = Path(__file__).parents[2] / "docs" / "schemas"
        for name in schemas:
            with self.subTest(name=name):
                document = json.loads((root / name).read_text(encoding="utf-8"))
                self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertFalse(document["additionalProperties"])
                self.assertTrue(document["required"])


def _input():
    from scripts.release_v2.advisories import AdvisoryValidationPolicy
    from scripts.release_v2.archive import ArchiveIndexV1
    from scripts.release_v2.evidence import QualificationBindingV1
    from scripts.release_v2.licenses import LicenseDisposition, LicenseEvidenceSource, LicensePolicyRecordV1, bind_license_report, build_license_report
    from scripts.release_v2.inventory import checksum_rows
    from scripts.release_v2.manifest import ManifestInputsV2
    from scripts.release_v2.sbom import bind_sbom, build_sbom
    from scripts.tests.test_release_v2_advisories import _fixture_report
    from scripts.tests.test_release_v2_evidence import _records

    build = BuildInputIdentityV2("build-input-v2", "a" * 40, "b" * 64, "1.0.0", "x86_64-unknown-linux-gnu", "linux", ("c" * 64,), "rust-1.97.1", "d" * 64, "e" * 64, "release", 10)
    entry = ArtifactEntry("NOTICE", "file", "0644", 7, hashlib.sha256(b"notice\n").hexdigest())
    candidate = hashlib.sha256(canonical_json([asdict(entry)])).hexdigest()
    inventory_sha = hashlib.sha256(canonical_json({"candidate_sha256": candidate, "entries": [asdict(entry)], "schema_version": "artifact-inventory-v2"})).hexdigest()
    inventory = ArtifactInventoryV2("artifact-inventory-v2", candidate, (entry,), inventory_sha)
    from scripts.release_v2.dependencies_types import DependencyPackageV1

    package = DependencyPackageV1("cargo", "component", "1.0.0", "https://crates.io/index", "a" * 64, "MIT", (), True)
    dependencies = dependency_inventory(package)
    build_sha = hashlib.sha256(canonical_json(asdict(build))).hexdigest()
    product = ProductTupleIdentityV1(build_sha, inventory_sha, "0" * 64, "0" * 64, "f" * 64, ("NOTICE",), "product-tuple-v1")
    product = bind_sbom(product, build_sbom(dependencies, product, structural_fixture=True))
    policy = (LicensePolicyRecordV1("MIT", LicenseDisposition.ALLOWED, LicenseEvidenceSource.COMMITTED_RECORD, False, "policy_reviewer", "approved_policy", None),)
    license_raw = build_license_report(dependencies, product, policy, (), artifact_inventory=inventory, notice_artifacts=(), source_date_epoch=10)
    product = bind_license_report(product, license_raw)
    subject = _subject(product)
    advisory_raw = _fixture_report(dependencies, product, inventory, subject)
    binding = QualificationBindingV1(subject.subject_sha256, build.source_tree_sha256, product_sha(product), inventory_sha, hashlib.sha256(advisory_raw).hexdigest(), "release")
    records = _records(binding)
    return ManifestInputsV2(build, inventory, dependencies, product, subject, ArchiveIndexV1("release-archive-index-v1", "1" * 64, "tar-ustar", 0, candidate, (entry,)), build_sbom(dependencies, product, structural_fixture=True), license_raw, advisory_raw, checksum_rows(inventory), records, binding, policy, (), (), AdvisoryValidationPolicy("osv_scanner", "1.0.0", "d" * 64, "OSV", "b" * 64, 9, 11), (entry,), "f" * 64, "e" * 64)


def product_sha(product: ProductTupleIdentityV1) -> str:
    return hashlib.sha256(canonical_json(asdict(product))).hexdigest()


def _subject(product: ProductTupleIdentityV1) -> QualificationSubjectIdentityV1:
    digest = product_sha(product)
    return QualificationSubjectIdentityV1(product.build_input_sha256, digest, hashlib.sha256(canonical_json({"build_input_sha256": product.build_input_sha256, "product_tuple_sha256": digest})).hexdigest())
