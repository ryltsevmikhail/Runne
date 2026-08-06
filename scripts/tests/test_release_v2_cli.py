import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.cli import _InputError, _epoch
from scripts.release_v2.fixture_loader import load_fixture_gate
from scripts.release_v2.fixtures import FIXTURE_SOURCE_SHA, SOURCE_DATE_EPOCH
from scripts.release_v2.gate import evaluate_gate
from scripts.release_v2.human_fixture_validation import snapshot_human_fixture


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "scripts/package-release-v2.sh"
VERIFY = ROOT / "scripts/verify-release-v2.sh"


class ReleaseV2CliTests(unittest.TestCase):
    def test_fixture_loader_reconstructs_gate_inputs_from_captured_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            self._run(PACKAGE, "--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH), check=True)
            loaded = load_fixture_gate(snapshot_human_fixture(output))
            result = evaluate_gate(loaded.manifest, context=loaded.context, fixture_mode=True)
            self.assertEqual(result.fixture_status.value, "STRUCTURAL_FIXTURE_VALID")
            self.assertEqual(result.failures, ())

    def test_package_generates_a_valid_structural_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            result = self._run(PACKAGE, "--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH))
            self.assertEqual(result.returncode, 0)
            document = self._canonical_result(result)
            self.assertEqual(document["fixture_status"], "STRUCTURAL_FIXTURE_VALID")
            self.assertFalse(document["production_approved"])
            self.assertTrue((output / "manifest.v2.json").is_file())
            self.assertEqual(json.loads((output / "build-input.v2.json").read_text(encoding="utf-8"))["source_revision"], FIXTURE_SOURCE_SHA)
            self.assertEqual(document["candidate_sha256"], json.loads((output / "manifest.v2.json").read_text(encoding="utf-8"))["candidate_sha256"])
            self.assertEqual(document["qualification_subject_sha256"], json.loads((output / "qualification-subject.v1.json").read_text(encoding="utf-8"))["subject_sha256"])

    def test_input_errors_are_typed_for_unknown_duplicate_and_nonempty_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir()
            (output / "occupied").write_bytes(b"x")
            cases = (
                ("--unknown",),
                ("--output", str(output), "--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH)),
                ("--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH)),
                ("--output", str(output), "--source-date-epoch", "not-a-decimal"),
            )
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    result = self._run(PACKAGE, *arguments)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(self._canonical_result(result)["error"]["code"], "InputInvalid")
                    self.assertNotIn(str(output), result.stderr)

    def test_verify_rejects_unknown_and_duplicate_fixture_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            self._run(PACKAGE, "--output", str(candidate), "--source-date-epoch", str(SOURCE_DATE_EPOCH), check=True)
            cases = (
                ("--unknown",),
                ("--fixture", "--fixture"),
            )
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    result = self._run(VERIFY, "--candidate", str(candidate), *arguments)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(self._canonical_result(result)["error"]["code"], "InputInvalid")

    def test_epoch_rejects_oversized_negative_overflow_and_bool_like_values(self) -> None:
        invalid = (
            ("five-thousand-digit", "9" * 5000),
            ("negative", "-1"),
            ("overflow", str(2**63)),
            ("bool-like", "true"),
            ("bool", True),
        )
        for label, value in invalid:
            with self.subTest(value=label):
                with self.assertRaises(_InputError):
                    _epoch(value)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            for label, value in invalid[:-1]:
                with self.subTest(cli_value=label):
                    result = self._run(PACKAGE, "--output", str(output), "--source-date-epoch", value)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(self._canonical_result(result)["error"]["code"], "InputInvalid")
                    self.assertFalse(output.exists())

    def test_fixture_verify_is_read_only_and_structural_errors_are_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            self._run(PACKAGE, "--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH), check=True)
            before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
            result = self._run(VERIFY, "--candidate", str(output), "--fixture")
            self.assertEqual(result.returncode, 0)
            document = self._canonical_result(result)
            self.assertEqual(document["fixture_status"], "STRUCTURAL_FIXTURE_VALID")
            self.assertFalse(document["production_approved"])
            self.assertEqual(before, {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()})
            (output / "human/changelog.md").write_bytes(b"changed\n")
            changed = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
            result = self._run(VERIFY, "--candidate", str(output), "--fixture")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(self._canonical_result(result)["error"]["code"], "ArtifactDigestMismatch")
            self.assertEqual(changed, {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()})

    def test_production_gate_is_currently_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            self._run(PACKAGE, "--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH), check=True)
            before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
            result = self._run(VERIFY, "--candidate", str(output))
            self.assertEqual(result.returncode, 1)
            document = self._canonical_result(result)
            self.assertEqual(document["overall_status"], "BLOCKED_EVIDENCE")
            self.assertEqual(document["production_gate"]["disposition"], "BLOCKED")
            self.assertFalse(document["production_approved"])
            manifest = json.loads((output / "manifest.v2.json").read_text(encoding="utf-8"))
            subject = json.loads((output / "qualification-subject.v1.json").read_text(encoding="utf-8"))
            self.assertEqual(document["candidate_sha256"], manifest["candidate_sha256"])
            self.assertEqual(document["qualification_subject_sha256"], subject["subject_sha256"])
            self.assertEqual({claim["subject_sha256"] for claim in document["claims"]}, {subject["subject_sha256"]})
            self.assertEqual(document["validation_scope"], "validated_structural_candidate_candidate_bound_blocked_claims")
            self.assertEqual(document["limitation"], {"task": "Task16", "status": "NOT_RUN"})
            self.assertEqual(before, {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()})

    def test_production_gate_reports_tampered_candidate_as_structural_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            self._run(PACKAGE, "--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH), check=True)
            target = output / "manifest.v2.json"
            target.write_bytes(target.read_bytes() + b" ")
            before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
            result = self._run(VERIFY, "--candidate", str(output))
            self.assertEqual(result.returncode, 1)
            document = self._canonical_result(result)
            self.assertEqual(document["error"]["code"], "ArtifactDigestMismatch")
            self.assertNotIn("claims", document)
            self.assertEqual(before, {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()})

    def test_semantic_tampering_with_recomputed_sidecars_returns_no_claims(self) -> None:
        mutations = (
            ("artifact-inventory.v2.json", lambda value: value["entries"][0].update({"sha256": "0" * 64})),
            ("product-tuple.v1.json", lambda value: value["components"].append("tampered")),
            ("qualification-evidence.v1.json", lambda value: value["records"][0].update({"payload_sha256": "0" * 64})),
            ("qualification-evidence.v1.json", lambda value: value["records"][0]["review"].update({"owner": "fixture_reviewer"})),
            ("fixture-result.v1.json", lambda value: value["production_gate"].update({"failure_code": "EvidenceMissing"})),
            ("provenance.v1.json", lambda value: value.update({"kind": "tampered_fixture"})),
            ("release-snapshot.v1.json", lambda value: value.update({"candidate_sha256": "0" * 64})),
        )
        for name, mutate in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "fixture"
                self._run(PACKAGE, "--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH), check=True)
                document = json.loads((output / name).read_text(encoding="utf-8"))
                mutate(document)
                (output / name).write_bytes(canonical_json(document))
                (output / f"{name}.sha256").write_text(f"{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}\n", encoding="utf-8")
                before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
                result = self._run(VERIFY, "--candidate", str(output), "--fixture")
                self.assertEqual(result.returncode, 1)
                report = self._canonical_result(result)
                self.assertNotEqual(report["error"]["code"], "InternalError")
                self.assertNotIn("claims", report)
                self.assertEqual(before, {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()})

    def test_malformed_license_policy_row_with_recomputed_sidecar_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            self._run(PACKAGE, "--output", str(output), "--source-date-epoch", str(SOURCE_DATE_EPOCH), check=True)
            name = "fixture-inputs.v1.json"
            document = json.loads((output / name).read_text(encoding="utf-8"))
            document["license_policy"].append({"unexpected": "row"})
            (output / name).write_bytes(canonical_json(document))
            (output / f"{name}.sha256").write_text(f"{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}\n", encoding="utf-8")
            result = self._run(VERIFY, "--candidate", str(output), "--fixture")
            self.assertEqual(result.returncode, 1)
            report = self._canonical_result(result)
            self.assertNotEqual(report["error"]["code"], "InternalError")
            self.assertNotIn("claims", report)

    def test_shell_wrappers_are_thin_and_local_only(self) -> None:
        forbidden = ("curl", "wget", "publish", "upload", "deploy", "sign", "notary", "network")
        for wrapper in (PACKAGE, VERIFY):
            with self.subTest(wrapper=wrapper.name):
                text = wrapper.read_text(encoding="utf-8")
                self.assertIn("set -euo pipefail", text)
                self.assertIn("exec python3", text)
                self.assertTrue(all(marker not in text.lower() for marker in forbidden))

    def _run(self, executable: Path, *arguments: str, check: bool = False) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(executable), *arguments], cwd=ROOT, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _canonical_result(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertTrue(result.stdout.endswith("\n"))
        document = json.loads(result.stdout)
        self.assertEqual(result.stdout.encode("utf-8"), canonical_json(document))
        return document
