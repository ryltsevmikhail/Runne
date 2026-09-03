import json
import os
import unittest
from dataclasses import replace
from unittest import mock

from scripts.macos_signing.models import FailureCode
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
from scripts.tests.macos_product_signing_runner_support import ProductRecordingRunner


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
            evidence_path=publication / "Runne-signing-evidence.v3.json",
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
        self.assertEqual(document["schema_version"], "macos-product-signing-evidence.v3")
        self.assertEqual(document["distribution"]["dmg_sha256"], outcome.evidence.dmg_sha256)
        self.assertEqual(
            document["commands"][0]["phase"],
            "inspect-provisioning-profile-app",
        )
        self.assertEqual(document["commands"][-1]["phase"], "validate-dmg")
        create_dmg = next(
            command
            for command in document["commands"]
            if command["phase"] == "create-dmg"
        )
        self.assertEqual(create_dmg["argv"][0], "create")
        self.assertEqual(
            create_dmg["argv"][4],
            ".runne-product-work/dmg-root",
        )

    def test_profile_for_another_app_stops_before_component_signing(self) -> None:
        runner = ProductRecordingRunner(self.root, invalid_profile=True)

        outcome = run_product_signing(self.request, runner, "darwin")

        self.assertEqual(
            getattr(outcome.failure, "code", None),
            FailureCode.ENTITLEMENTS_MISMATCH,
        )
        self.assertEqual(
            getattr(outcome.failure, "phase", None),
            "inspect-provisioning-profile-app",
        )
        self.assertEqual(
            [command.phase for command in runner.commands],
            ["inspect-provisioning-profile-app"],
        )

    def test_helper_profile_for_another_application_id_stops_before_signing(self) -> None:
        runner = ProductRecordingRunner(self.root, invalid_service_profile=True)

        outcome = run_product_signing(self.request, runner, "darwin")

        self.assertEqual(outcome.failure.code, FailureCode.ENTITLEMENTS_MISMATCH)
        self.assertEqual(
            outcome.failure.phase,
            "inspect-provisioning-profile-credential-service",
        )
        self.assertEqual(
            [command.phase for command in runner.commands],
            [
                "inspect-provisioning-profile-app",
                "inspect-provisioning-profile-credential-service",
            ],
        )

    def test_empty_embedded_app_entitlements_stop_before_notarization(self) -> None:
        runner = ProductRecordingRunner(self.root, empty_app_entitlements=True)

        outcome = run_product_signing(self.request, runner, "darwin")

        self.assertEqual(
            getattr(outcome.failure, "code", None),
            FailureCode.ENTITLEMENTS_MISMATCH,
        )
        self.assertEqual(getattr(outcome.failure, "phase", None), "entitlements-app")
        self.assertEqual(runner.commands[-1].phase, "entitlements-app")
        self.assertFalse(self.request.output_dmg.exists())

    def test_helper_designated_requirement_must_name_exact_identifier(self) -> None:
        runner = ProductRecordingRunner(
            self.root,
            invalid_requirement_role="credential-service",
        )

        outcome = run_product_signing(self.request, runner, "darwin")

        self.assertEqual(outcome.failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        self.assertEqual(outcome.failure.phase, "requirement-credential-service")
        self.assertEqual(runner.commands[-1].phase, "requirement-credential-service")

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
        index = next(
            index
            for index, record in enumerate(records)
            if record.template.phase == "package-app-zip"
        )
        record = records[index]
        records[index] = replace(
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
        self.assertEqual(outcome.failure.phase, "sign-credential-service")
        self.assertEqual(
            [command.phase for command in runner.commands],
            [
                "inspect-provisioning-profile-app",
                "inspect-provisioning-profile-credential-service",
                "sign-credential-service",
            ],
        )
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
