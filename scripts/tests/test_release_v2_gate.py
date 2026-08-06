import hashlib
import os
import subprocess
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from scripts.release_v2.advisories import AdvisoryValidationPolicy
from scripts.release_v2.archive import build_archive
from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.dependencies_types import DependencyPackageV1
from scripts.release_v2.gate import GateVerificationContext, evaluate_gate
from scripts.release_v2.inventory import build_inventory, capture_tree_bytes, checksum_rows
from scripts.release_v2.licenses import LicenseDisposition, LicenseEvidenceSource, LicensePolicyRecordV1, bind_license_report, build_license_report
from scripts.release_v2.manifest import ManifestInputsV2, assemble_manifest, manifest_bytes
from scripts.release_v2.model import BuildInputIdentityV2, FailureCodeV1, ProductTupleIdentityV1, QualificationSubjectIdentityV1
from scripts.release_v2.preflight import BuildRequest, build_input_identity
from scripts.release_v2.sbom import bind_sbom, build_sbom
from scripts.tests.release_v2_support import dependency_inventory
from scripts.tests.test_release_v2_advisories import _fixture_report
from scripts.tests.test_release_v2_evidence import _records


class GateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.source, self.candidate, output = root / "source", root / "candidate", root / "output"
        self.source.mkdir()
        for name, value in (("Cargo.lock", b"cargo\n"), ("pnpm-lock.yaml", b"pnpm\n"), ("NOTICE", b"notice\n")):
            (self.source / name).write_bytes(value)
        self._git(self.source, "init")
        self._git(self.source, "add", ".")
        self._git(self.source, "commit", "-m", "fixture")
        self.candidate.mkdir()
        (self.candidate / "NOTICE").write_bytes(b"notice\n")
        os.chmod(self.candidate / "NOTICE", 0o644)
        request = BuildRequest("1.0.0", "x86_64-unknown-linux-gnu", "linux", ("a" * 64,), "rust-1.97.1", "release", 10)
        build = build_input_identity(self.source, request)
        inventory = build_inventory(self.candidate, capture_tree_bytes(self.candidate).entries)
        package = DependencyPackageV1("cargo", "component", "1.0.0", "https://crates.io/index", "a" * 64, "MIT", (), True)
        dependencies = dependency_inventory(package)
        build_sha = hashlib.sha256(canonical_json(asdict(build))).hexdigest()
        product = ProductTupleIdentityV1(build_sha, inventory.inventory_sha256, "0" * 64, "0" * 64, "f" * 64, tuple(entry.path for entry in inventory.entries), "product-tuple-v1")
        product = bind_sbom(product, build_sbom(dependencies, product, structural_fixture=True))
        policy = (LicensePolicyRecordV1("MIT", LicenseDisposition.ALLOWED, LicenseEvidenceSource.COMMITTED_RECORD, False, "policy_reviewer", "approved_policy", None),)
        license_raw = build_license_report(dependencies, product, policy, (), artifact_inventory=inventory, notice_artifacts=(), source_date_epoch=10)
        product = bind_license_report(product, license_raw)
        product_sha = hashlib.sha256(canonical_json(asdict(product))).hexdigest()
        subject = QualificationSubjectIdentityV1(build_sha, product_sha, hashlib.sha256(canonical_json({"build_input_sha256": build_sha, "product_tuple_sha256": product_sha})).hexdigest())
        advisory_raw = _fixture_report(dependencies, product, inventory, subject)
        from scripts.release_v2.evidence import QualificationBindingV1
        binding = QualificationBindingV1(subject.subject_sha256, build.source_tree_sha256, product_sha, inventory.inventory_sha256, hashlib.sha256(advisory_raw).hexdigest(), "release")
        output.mkdir()
        archive = build_archive(self.candidate, output, build.source_date_epoch, inventory.candidate_sha256)
        inputs = ManifestInputsV2(build, inventory, dependencies, product, subject, archive, build_sbom(dependencies, product, structural_fixture=True), license_raw, advisory_raw, checksum_rows(inventory), _records(binding), binding, policy, (), (), AdvisoryValidationPolicy("osv_scanner", "1.0.0", "d" * 64, "OSV", "b" * 64, 9, 11), inventory.entries, "f" * 64, "e" * 64)
        self.manifest = assemble_manifest(inputs)
        self.context = GateVerificationContext(self.source, self.candidate, output / "archive.tar", output / "archive-index.v1.json", manifest_bytes(self.manifest), advisory_raw, checksum_rows(inventory))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_real_context_passes_and_preserves_source_and_candidate(self) -> None:
        before = tuple(path.read_bytes() for path in (self.source / "NOTICE", self.candidate / "NOTICE"))
        result = evaluate_gate(self.manifest, context=self.context, fixture_mode=True)
        self.assertEqual(result.fixture_status.value, "STRUCTURAL_FIXTURE_VALID")
        self.assertEqual(tuple(path.read_bytes() for path in (self.source / "NOTICE", self.candidate / "NOTICE")), before)

    def test_missing_or_tampered_archive_blocks(self) -> None:
        self.context.archive_path.unlink()
        result = evaluate_gate(self.manifest, context=self.context, fixture_mode=True)
        self.assertTrue(result.failures)
        self._assert_unverified_fixture(result)
        self.context.archive_index_path.unlink()
        build_archive(self.candidate, self.context.archive_path.parent, 10, self.manifest.inventory.candidate_sha256)
        self.context.archive_path.write_bytes(self.context.archive_path.read_bytes() + b"tampered")
        result = evaluate_gate(self.manifest, context=self.context, fixture_mode=True)
        self.assertTrue(result.failures)
        self._assert_unverified_fixture(result)

    def test_candidate_mutation_blocks_without_repair(self) -> None:
        target = self.candidate / "NOTICE"
        target.write_bytes(b"changed\n")
        result = evaluate_gate(self.manifest, context=self.context, fixture_mode=True)
        self.assertTrue(result.failures)
        self._assert_unverified_fixture(result)
        self.assertEqual(target.read_bytes(), b"changed\n")

    def test_source_mutation_during_archive_verification_blocks_without_repair(self) -> None:
        from scripts.release_v2 import gate

        target = self.source / "NOTICE"
        original = gate.verify_archive_index

        def mutate(*args, **kwargs):
            target.write_bytes(b"changed\n")
            return original(*args, **kwargs)

        with patch("scripts.release_v2.gate.verify_archive_index", side_effect=mutate):
            result = evaluate_gate(self.manifest, context=self.context, fixture_mode=True)
        self.assertEqual(tuple(failure.code for failure in result.failures), (FailureCodeV1.INPUT_MUTATION_DETECTED,))
        self.assertEqual(result.claims, ())
        self._assert_unverified_fixture(result)
        self.assertEqual(target.read_bytes(), b"changed\n")

    def test_final_capture_error_is_input_mutation(self) -> None:
        from scripts.release_v2 import gate

        original, calls = gate.capture_repository, 0

        def capture(root):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("final capture failed")
            return original(root)

        with patch("scripts.release_v2.gate.capture_repository", side_effect=capture):
            result = evaluate_gate(self.manifest, context=self.context, fixture_mode=True)
        self.assertEqual(tuple(failure.code for failure in result.failures), (FailureCodeV1.INPUT_MUTATION_DETECTED,))
        self._assert_unverified_fixture(result)

    def test_fixture_mode_requires_exact_bool_and_typed_failure(self) -> None:
        result = evaluate_gate(self.manifest, context=self.context, fixture_mode=1)
        self.assertEqual((result.production_gate.failure_code, result.failures[0].code), (FailureCodeV1.PRODUCTION_GATE_BLOCKED, FailureCodeV1.MANIFEST_INVALID))
        self._assert_unverified_fixture(result)

    def test_source_only_preflight_does_not_treat_candidate_staging_as_git(self) -> None:
        from scripts.release_v2.gate import _preflight_source_only

        with patch("scripts.release_v2.gate.preflight_candidate") as preflight:
            _preflight_source_only(self.source, self.manifest.inputs.build)
        preflight.assert_called_once_with(self.source, self.source, self.manifest.inputs.build)

    def _assert_unverified_fixture(self, result) -> None:
        self.assertEqual(result.overall_status.value, "BLOCKED_EVIDENCE")
        self.assertIsNone(result.fixture_status)
        self.assertNotIn("fixture_status", result.as_dict())

    @staticmethod
    def _git(root: Path, *arguments: str) -> None:
        subprocess.run(["git", "-C", str(root), "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", *arguments], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
