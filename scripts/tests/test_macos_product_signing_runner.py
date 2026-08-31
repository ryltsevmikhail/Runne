import unittest
from unittest import mock

from scripts.macos_signing.models import CommandResult, FailureCode
from scripts.macos_signing.parsers import parse_codesign_result
from scripts.macos_signing.product_commands import build_product_distribution_commands
from scripts.macos_signing.product_layout import APP_ZIP_RELATIVE, DMG_RELATIVE
from scripts.macos_signing.product_models import ProductionCredentialReferences
from scripts.macos_signing.product_runner import ProductLiveRunner
from scripts.tests.macos_product_signing_support import validated_product_candidate


class MacOSProductSigningRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary, self.root, self.candidate = validated_product_candidate()
        self.temporary = temporary
        self.addCleanup(temporary.cleanup)
        self.keychain = self.root.resolve() / "runne-release.keychain"
        self.keychain.write_bytes(b"keychain fixture\n")
        self.work = self.root / ".runne-product-work"
        (self.work / "dmg-root").mkdir(parents=True, mode=0o700)
        self.work.chmod(0o700)
        credentials = ProductionCredentialReferences(
            "A" * 40,
            "runne-notary-01",
            self.keychain,
        )
        self.commands = build_product_distribution_commands(
            self.candidate,
            credentials,
            APP_ZIP_RELATIVE,
            DMG_RELATIVE,
        )

    def test_packaging_resolves_contained_paths_and_uses_fixed_environment(self) -> None:
        command = self.commands[0]

        def create_output(argv, **_kwargs):
            output = argv[-1]
            with open(output, "xb") as handle:
                handle.write(b"zip\n")
            return mock.Mock(returncode=0)

        with (
            mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True),
            mock.patch("scripts.macos_signing.runner.os.access", return_value=True),
            mock.patch(
                "scripts.macos_signing.runner.subprocess.run",
                side_effect=create_output,
            ) as run,
        ):
            result = ProductLiveRunner(self.root).run(command)

        self.assertEqual(result.exit_code, 0)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/ditto")
        self.assertEqual(argv[-2], str((self.root / "Runne.app").resolve()))
        self.assertEqual(
            argv[-1],
            str(self.root.resolve() / APP_ZIP_RELATIVE),
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(set(run.call_args.kwargs["env"]), {"PATH", "LANG", "LC_ALL"})

    def test_existing_or_symlinked_output_is_rejected_before_subprocess(self) -> None:
        output = self.root / APP_ZIP_RELATIVE
        output.write_bytes(b"existing\n")
        with mock.patch("scripts.macos_signing.runner.subprocess.run") as run:
            result = ProductLiveRunner(self.root).run(self.commands[0])
        self.assertEqual(parse_codesign_result(result), FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        run.assert_not_called()

    def test_symlinked_notary_input_is_rejected_before_subprocess(self) -> None:
        target = self.root / "actual.zip"
        target.write_bytes(b"zip\n")
        (self.root / APP_ZIP_RELATIVE).symlink_to(target)
        with mock.patch("scripts.macos_signing.runner.subprocess.run") as run:
            result = ProductLiveRunner(self.root).run(self.commands[1])
        self.assertEqual(parse_codesign_result(result), FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        run.assert_not_called()

    def test_runner_exception_is_redacted_to_typed_failure(self) -> None:
        command = self.commands[0]
        with (
            mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True),
            mock.patch("scripts.macos_signing.runner.os.access", return_value=True),
            mock.patch(
                "scripts.macos_signing.runner.subprocess.run",
                side_effect=OSError("SYNTHETIC-RAW-MARKER"),
            ),
        ):
            result = ProductLiveRunner(self.root).run(command)
        self.assertEqual(result, CommandResult(127, "", FailureCode.TOOL_UNAVAILABLE.value))
        self.assertNotIn("SYNTHETIC-RAW-MARKER", repr(result))

    def test_notary_keychain_symlink_is_rejected_before_subprocess(self) -> None:
        target = self.root / "actual.keychain"
        target.write_bytes(b"keychain\n")
        self.keychain.unlink()
        self.keychain.symlink_to(target)
        (self.root / APP_ZIP_RELATIVE).write_bytes(b"zip\n")

        with mock.patch("scripts.macos_signing.runner.subprocess.run") as run:
            result = ProductLiveRunner(self.root).run(self.commands[1])

        self.assertEqual(
            parse_codesign_result(result),
            FailureCode.ARTIFACT_IDENTITY_MISMATCH,
        )
        run.assert_not_called()

    def test_replaced_private_workspace_is_rejected_before_subprocess(self) -> None:
        original = self.root / "original-work"
        self.work.rename(original)
        self.work.symlink_to(original, target_is_directory=True)

        with mock.patch("scripts.macos_signing.runner.subprocess.run") as run:
            result = ProductLiveRunner(self.root).run(self.commands[0])

        self.assertEqual(
            parse_codesign_result(result),
            FailureCode.ARTIFACT_IDENTITY_MISMATCH,
        )
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
