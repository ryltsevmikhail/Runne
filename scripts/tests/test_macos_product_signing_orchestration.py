import json
import os
import plistlib
import shutil
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.macos_signing.models import CommandResult, FailureCode
from scripts.macos_signing.product_evidence import normalize_product_evidence
from scripts.macos_signing.product_models import (
    ExternalCommandTemplate,
    ProductExecutionRecord,
    ProductSigningRunRequest,
    ProductSigningStage,
    ProductionCredentialReferences,
)
from scripts.macos_signing.product_orchestration import run_product_signing
from scripts.tests.macos_product_signing_support import product_candidate_fixture

_TEAM_ID = "758F9Z45SR"


class ProductRecordingRunner:
    def __init__(self, root: Path, failure_phase: str | None = None, mutate: bool = True) -> None:
        self.root = root
        self.failure_phase = failure_phase
        self.mutate = mutate
        self.commands = []

    def run(self, command):
        self.commands.append(command)
        if command.phase == self.failure_phase:
            return CommandResult(1, "SYNTHETIC-RAW-MARKER", "UNKNOWN_STATUS")
        if self.mutate:
            self._apply_side_effect(command.phase)
        return self._success(command.phase)

    def _apply_side_effect(self, phase: str) -> None:
        macos = self.root / "Runne.app" / "Contents" / "MacOS"
        if phase == "sign-daemon":
            (macos / "runned").write_bytes(b"signed daemon\n")
        elif phase == "sign-cli":
            (macos / "runne").write_bytes(b"signed cli\n")
        elif phase == "sign-app":
            (macos / "runne-desktop").write_bytes(b"signed app\n")
        elif phase == "package-app-zip":
            (self.root / ".runne-product-work" / "app.zip").write_bytes(
                b"signed app zip\n"
            )
        elif phase == "staple-app":
            ticket = self.root / "Runne.app" / "Contents" / "_CodeSignature" / "ticket"
            ticket.parent.mkdir(exist_ok=True)
            ticket.write_bytes(b"ticket\n")
        elif phase == "create-dmg":
            (self.root / ".runne-product-work" / "Runne.dmg").write_bytes(b"dmg\n")
        elif phase == "stage-dmg-app":
            shutil.copytree(
                self.root / "Runne.app",
                self.root / ".runne-product-work" / "dmg-root" / "Runne.app",
            )
        elif phase == "sign-dmg":
            (self.root / ".runne-product-work" / "Runne.dmg").write_bytes(
                b"signed dmg\n"
            )
        elif phase == "staple-dmg":
            (self.root / ".runne-product-work" / "Runne.dmg").write_bytes(
                b"stapled dmg\n"
            )

    def _success(self, phase: str) -> CommandResult:
        if phase.startswith("metadata-"):
            role = phase.removeprefix("metadata-")
            identifier = {
                "app": "com.runne.desktop",
                "cli": "runne",
                "daemon": "runned",
            }[role]
            return CommandResult(
                0,
                "",
                "\n".join(
                    (
                        f"Identifier={identifier}",
                        f"TeamIdentifier={_TEAM_ID}",
                        "Authority=Developer ID Application: Synthetic",
                        "CDHash=" + "a" * 40,
                        "CodeDirectory v=20500 flags=0x10000(runtime)",
                    )
                ),
            )
        if phase.startswith("requirement-"):
            return CommandResult(0, "", "designated => synthetic requirement")
        if phase.startswith("entitlements-"):
            return CommandResult(0, plistlib.dumps({}).decode(), "")
        if phase.startswith("notary-"):
            return CommandResult(0, '{"status":"Accepted"}', "")
        return CommandResult(0, "", "")


class MacOSProductSigningOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary, self.root, candidate, _ = product_candidate_fixture()
        self.temporary = temporary
        self.addCleanup(temporary.cleanup)
        keychain = self.root.resolve() / "runne-release.keychain"
        keychain.write_bytes(b"keychain fixture\n")
        publication = self.root / "published"
        self.request = ProductSigningRunRequest(
            candidate=candidate,
            credentials=ProductionCredentialReferences(
                "A" * 40,
                "runne-notary-01",
                keychain,
            ),
            output_dmg=publication / "Runne.dmg",
            evidence_path=publication / "Runne-signing-evidence.v2.json",
        )

    def test_success_publishes_notarized_dmg_and_redacted_evidence(self) -> None:
        runner = ProductRecordingRunner(self.root)
        outcome = run_product_signing(self.request, runner, "darwin")

        self.assertEqual(outcome.stage, ProductSigningStage.COMPLETE)
        self.assertIsNone(outcome.failure)
        self.assertTrue(self.request.output_dmg.is_file())
        self.assertTrue(self.request.evidence_path.is_file())
        self.assertFalse((self.root / ".runne-product-work").exists())
        encoded = normalize_product_evidence(outcome.evidence)
        self.assertEqual(encoded, self.request.evidence_path.read_bytes())
        self.assertNotIn(b"A" * 40, encoded)
        self.assertNotIn(b"runne-notary-01", encoded)
        self.assertNotIn(b"SYNTHETIC-RAW-MARKER", encoded)
        document = json.loads(encoded)
        self.assertEqual(document["distribution"]["dmg_sha256"], outcome.evidence.dmg_sha256)
        self.assertEqual(document["commands"][0]["phase"], "sign-daemon")
        self.assertEqual(document["commands"][-1]["phase"], "validate-dmg")
        self.assertEqual(document["commands"][21]["argv"][0], "create")
        self.assertEqual(
            document["commands"][21]["argv"][4],
            ".runne-product-work/dmg-root",
        )

    def test_dmg_and_evidence_are_published_by_one_directory_rename(self) -> None:
        real_replace = os.replace
        with mock.patch(
            "scripts.macos_signing.product_workspace.os.replace",
            wraps=real_replace,
        ) as replace_path:
            outcome = run_product_signing(
                self.request,
                ProductRecordingRunner(self.root),
                "darwin",
            )

        self.assertEqual(outcome.stage, ProductSigningStage.COMPLETE)
        self.assertEqual(replace_path.call_count, 1)
        self.assertEqual(
            replace_path.call_args.args,
            (
                self.root.resolve() / ".runne-product-work",
                self.root.resolve() / "published",
            ),
        )

    def test_failed_atomic_publication_removes_only_private_workspace(self) -> None:
        with mock.patch(
            "scripts.macos_signing.product_workspace.os.replace",
            side_effect=OSError("synthetic rename failure"),
        ):
            outcome = run_product_signing(
                self.request,
                ProductRecordingRunner(self.root),
                "darwin",
            )

        self.assertEqual(outcome.failure.code, FailureCode.UNKNOWN_STATUS)
        self.assertEqual(outcome.failure.phase, "orchestration")
        self.assertFalse((self.root / ".runne-product-work").exists())
        self.assertFalse((self.root / "published").exists())

    def test_evidence_rejects_missing_command_history(self) -> None:
        outcome = run_product_signing(
            self.request,
            ProductRecordingRunner(self.root),
            "darwin",
        )

        with self.assertRaises(ValueError):
            normalize_product_evidence(replace(outcome.evidence, commands=()))

    def test_evidence_rejects_unredacted_or_forged_command(self) -> None:
        outcome = run_product_signing(
            self.request,
            ProductRecordingRunner(self.root),
            "darwin",
        )
        records = list(outcome.evidence.commands)
        records[0] = ProductExecutionRecord(
            ExternalCommandTemplate(
                "sign-daemon",
                "/usr/bin/codesign",
                ("--force", "--sign", "RAW-IDENTITY", "Runne.app"),
            ),
            "success",
        )

        with self.assertRaises(ValueError):
            normalize_product_evidence(
                replace(outcome.evidence, commands=tuple(records))
            )

    def test_evidence_rejects_mutated_distribution_argv(self) -> None:
        outcome = run_product_signing(
            self.request,
            ProductRecordingRunner(self.root),
            "darwin",
        )
        records = list(outcome.evidence.commands)
        record = records[20]
        records[20] = replace(
            record,
            template=replace(record.template, argv=("create", "forged")),
        )

        with self.assertRaises(ValueError):
            normalize_product_evidence(
                replace(outcome.evidence, commands=tuple(records))
            )

    def test_failure_stops_prefix_and_publishes_nothing(self) -> None:
        runner = ProductRecordingRunner(self.root, "notary-app-submit")
        outcome = run_product_signing(self.request, runner, "darwin")

        self.assertEqual(outcome.failure.code, FailureCode.UNKNOWN_STATUS)
        self.assertEqual(outcome.failure.phase, "notary-app-submit")
        self.assertEqual(runner.commands[-1].phase, "notary-app-submit")
        self.assertFalse(self.request.output_dmg.exists())
        self.assertFalse(self.request.evidence_path.exists())
        self.assertFalse((self.root / ".runne-product-work").exists())

    def test_non_macos_and_preexisting_outputs_fail_before_runner(self) -> None:
        runner = ProductRecordingRunner(self.root)
        unsupported = run_product_signing(self.request, runner, "linux")
        self.assertEqual(unsupported.failure.code, FailureCode.UNSUPPORTED_PLATFORM)
        self.assertEqual(runner.commands, [])

        self.request.output_dmg.parent.mkdir()
        self.request.output_dmg.write_bytes(b"existing\n")
        blocked = run_product_signing(self.request, runner, "darwin")
        self.assertEqual(blocked.failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        self.assertEqual(runner.commands, [])

    def test_sign_command_must_change_bound_component(self) -> None:
        runner = ProductRecordingRunner(self.root, mutate=False)
        outcome = run_product_signing(self.request, runner, "darwin")

        self.assertEqual(outcome.failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        self.assertEqual(outcome.failure.phase, "sign-daemon")
        self.assertEqual(len(runner.commands), 1)
        self.assertFalse(self.request.output_dmg.exists())

    def test_reserved_or_aliased_output_names_fail_before_runner(self) -> None:
        cases = (
            replace(self.request, output_dmg=self.root / "output.bin"),
            replace(self.request, evidence_path=self.root / "evidence.txt"),
            replace(
                self.request,
                evidence_path=self.request.output_dmg,
            ),
            replace(
                self.request,
                evidence_path=self.root / "published" / ".runne-product-notary.zip",
            ),
            replace(
                self.request,
                output_dmg=self.root / "other" / "Runne.dmg",
            ),
        )
        for request in cases:
            with self.subTest(request=request):
                runner = ProductRecordingRunner(self.root)
                outcome = run_product_signing(request, runner, "darwin")
                self.assertEqual(
                    outcome.failure.code,
                    FailureCode.ARTIFACT_IDENTITY_MISMATCH,
                )
                self.assertEqual(runner.commands, [])


if __name__ == "__main__":
    unittest.main()
