import json
from pathlib import Path
import unittest
from dataclasses import asdict
from unittest import mock

from scripts.macos_signing.command_grammar import parse_command_spec
from scripts.macos_signing.models import CommandSpec
from scripts.macos_signing.product_commands import (
    build_product_distribution_commands,
    build_product_notary_submit_command,
    build_product_signing_commands,
    redact_external_command,
)
from scripts.macos_signing.product_models import ProductionCredentialReferences
from scripts.macos_signing.runner import LiveRunner
from scripts.tests.macos_product_signing_support import validated_product_candidate


class MacOSProductSigningCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory, self.root, self.candidate = validated_product_candidate()
        self.temporary_directory = temporary_directory
        self.addCleanup(temporary_directory.cleanup)
        self.keychain = self.root / "runne-release.keychain"
        self.keychain.write_bytes(b"keychain fixture\n")
        self.credentials = ProductionCredentialReferences(
            signing_identity_ref="A" * 40,
            notary_profile_ref="runne-notary-01",
            notary_keychain_ref=self.keychain,
        )

    def test_component_commands_use_canonical_order_and_secure_timestamp(self) -> None:
        commands = build_product_signing_commands(self.candidate, self.credentials)

        self.assertEqual(
            tuple(command.phase for command in commands),
            (
                "inspect-provisioning-profile-app",
                "inspect-provisioning-profile-credential-service",
            )
            + tuple(
                f"{operation}-{role}"
                for role in ("credential-service", "daemon", "cli", "app")
                for operation in (
                    "sign",
                    "verify",
                    "metadata",
                    "requirement",
                    "entitlements",
                )
            ),
        )
        for command in commands:
            if command.phase.startswith("inspect-provisioning-profile-"):
                self.assertEqual(command.program, "/usr/bin/security")
                self.assertEqual(command.argv[:3], ("cms", "-D", "-i"))
                self.assertTrue(command.argv[3].endswith("embedded.provisionprofile"))
                continue
            parsed = parse_command_spec(command)
            self.assertIsNotNone(parsed)
            if command.phase == "verify-app":
                self.assertEqual(
                    command.argv[:3], ("--verify", "--deep", "--strict")
                )
            else:
                self.assertNotIn("--deep", command.argv)
            if command.phase.startswith("sign-"):
                self.assertEqual(
                    command.argv[:8],
                    (
                        "--force",
                        "--sign",
                        "A" * 40,
                        "--timestamp",
                        "--options",
                        "runtime",
                        "--entitlements",
                        "service.plist"
                        if command.phase == "sign-credential-service"
                        else f"{command.phase.removeprefix('sign-')}.plist",
                    ),
                )
                self.assertTrue(parsed.hardened_runtime)
        metadata = tuple(
            command for command in commands if command.phase.startswith("metadata-")
        )
        self.assertTrue(metadata)
        self.assertTrue(all(command.argv[0] == "-dvvv" for command in metadata))

    def test_external_templates_redact_identity_reference(self) -> None:
        commands = build_product_signing_commands(self.candidate, self.credentials)
        templates = tuple(redact_external_command(command) for command in commands)
        encoded = json.dumps([asdict(template) for template in templates], sort_keys=True)

        self.assertNotIn(self.credentials.signing_identity_ref, encoded)
        self.assertNotIn(self.credentials.notary_profile_ref, encoded)
        helper = next(
            template for template in templates if template.phase == "sign-credential-service"
        )
        self.assertEqual(
            helper.argv,
            (
                "--force",
                "--sign",
                "<SIGNING_IDENTITY_REF>",
                "--timestamp",
                "--options",
                "runtime",
                "--entitlements",
                "service.plist",
                "Runne.app/Contents/Library/Helpers/RunneCredentialService.app",
            ),
        )

    def test_notary_command_uses_only_keychain_backed_references(self) -> None:
        command = build_product_notary_submit_command(
            "Runne-signed.zip",
            self.credentials,
        )
        self.assertEqual(
            command.argv,
            (
                "notarytool",
                "submit",
                "Runne-signed.zip",
                "--keychain-profile",
                "runne-notary-01",
                "--keychain",
                str(self.keychain),
                "--wait",
                "--output-format",
                "json",
            ),
        )
        template = redact_external_command(command)
        self.assertEqual(template.argv[4], "<NOTARY_PROFILE_REF>")
        self.assertEqual(template.argv[6], "<NOTARY_KEYCHAIN_REF>")
        self.assertNotIn("runne-notary-01", json.dumps(asdict(template)))
        self.assertNotIn(str(self.keychain), json.dumps(asdict(template)))
        for forbidden in (
            "--password",
            "--key",
            "--key-id",
            "--issuer",
            "--sync",
        ):
            self.assertNotIn(forbidden, command.argv)

    def test_distribution_templates_cover_app_notary_and_notarized_dmg(self) -> None:
        commands = build_product_distribution_commands(
            self.candidate,
            self.credentials,
            ".runne-product-work/app.zip",
            ".runne-product-work/Runne.dmg",
        )
        self.assertEqual(
            tuple(command.phase for command in commands),
            (
                "package-app-zip",
                "notary-app-submit",
                "staple-app",
                "validate-app",
                "gatekeeper-app",
                "stage-dmg-app",
                "create-dmg",
                "sign-dmg",
                "verify-dmg",
                "notary-dmg-submit",
                "staple-dmg",
                "validate-dmg",
            ),
        )
        templates = tuple(redact_external_command(command) for command in commands)
        encoded = json.dumps([asdict(template) for template in templates], sort_keys=True)
        self.assertNotIn(self.credentials.signing_identity_ref, encoded)
        self.assertNotIn(self.credentials.notary_profile_ref, encoded)
        self.assertNotIn(str(self.credentials.notary_keychain_ref), encoded)
        self.assertEqual(
            templates[6].argv,
            (
                "create",
                "-volname",
                "Runne",
                "-srcfolder",
                ".runne-product-work/dmg-root",
                "-format",
                "UDZO",
                ".runne-product-work/Runne.dmg",
            ),
        )
        self.assertEqual(templates[7].argv[2], "<SIGNING_IDENTITY_REF>")
        self.assertEqual(templates[9].argv[4], "<NOTARY_PROFILE_REF>")
        self.assertEqual(templates[9].argv[6], "<NOTARY_KEYCHAIN_REF>")

    def test_credential_references_are_opaque_and_repr_safe(self) -> None:
        self.assertNotIn("A" * 40, repr(self.credentials))
        self.assertNotIn("runne-notary-01", repr(self.credentials))
        self.assertNotIn(str(self.keychain), repr(self.credentials))
        for identity, profile, keychain in (
            ("short", "runne-notary-01", self.keychain),
            ("A" * 40, "--password", self.keychain),
            ("A" * 40, "contains space", self.keychain),
            ("A" * 40, "path/profile", self.keychain),
            ("A" * 40, "runne-notary-01", Path("relative.keychain")),
        ):
            with self.subTest(identity=identity, profile=profile, keychain=keychain):
                with self.assertRaises(ValueError):
                    ProductionCredentialReferences(identity, profile, keychain)

    def test_secret_bearing_credential_options_are_not_command_inputs(self) -> None:
        for forbidden in (
            "--password",
            "--key",
            "--key-id",
            "--issuer",
            "--sync",
            "--apple-id",
            "--team-id",
        ):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(ValueError):
                    CommandSpec("forged", "/usr/bin/xcrun", (forbidden, "value"), ".")

    def test_live_boundary_uses_fixed_environment_without_identity_discovery(self) -> None:
        command = next(
            command
            for command in build_product_signing_commands(
                self.candidate,
                self.credentials,
            )
            if command.phase == "sign-daemon"
        )
        with (
            mock.patch("scripts.macos_signing.runner.Path.is_file", return_value=True),
            mock.patch("scripts.macos_signing.runner.os.access", return_value=True),
            mock.patch(
                "scripts.macos_signing.runner.subprocess.run",
                return_value=mock.Mock(returncode=0),
            ) as run,
        ):
            result = LiveRunner(self.root).run(command)

        self.assertEqual(result.exit_code, 0)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/codesign")
        self.assertEqual(argv[3], "A" * 40)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(
            run.call_args.kwargs["env"],
            {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )


if __name__ == "__main__":
    unittest.main()
