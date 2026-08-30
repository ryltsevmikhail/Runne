import json
import unittest
from dataclasses import asdict
from unittest import mock

from scripts.macos_signing.command_grammar import parse_command_spec
from scripts.macos_signing.models import CommandSpec
from scripts.macos_signing.product_commands import (
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
        self.credentials = ProductionCredentialReferences(
            signing_identity_ref="A" * 40,
            notary_profile_ref="runne-notary-01",
        )

    def test_component_commands_use_canonical_order_and_secure_timestamp(self) -> None:
        commands = build_product_signing_commands(self.candidate, self.credentials)

        self.assertEqual(
            tuple(command.phase for command in commands),
            tuple(
                f"{operation}-{role}"
                for role in ("daemon", "cli", "app")
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
            parsed = parse_command_spec(command)
            self.assertIsNotNone(parsed)
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
                        f"{command.phase.removeprefix('sign-')}.plist",
                    ),
                )
                self.assertTrue(parsed.hardened_runtime)

    def test_external_templates_redact_identity_reference(self) -> None:
        commands = build_product_signing_commands(self.candidate, self.credentials)
        templates = tuple(redact_external_command(command) for command in commands)
        encoded = json.dumps([asdict(template) for template in templates], sort_keys=True)

        self.assertNotIn(self.credentials.signing_identity_ref, encoded)
        self.assertNotIn(self.credentials.notary_profile_ref, encoded)
        self.assertEqual(
            templates[0].argv,
            (
                "--force",
                "--sign",
                "<SIGNING_IDENTITY_REF>",
                "--timestamp",
                "--options",
                "runtime",
                "--entitlements",
                "daemon.plist",
                "Runne.app/Contents/MacOS/runned",
            ),
        )

    def test_notary_command_uses_only_opaque_keychain_profile(self) -> None:
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
                "--wait",
                "--output-format",
                "json",
            ),
        )
        template = redact_external_command(command)
        self.assertEqual(template.argv[4], "<NOTARY_PROFILE_REF>")
        self.assertNotIn("runne-notary-01", json.dumps(asdict(template)))
        for forbidden in (
            "--password",
            "--key",
            "--key-id",
            "--issuer",
            "--sync",
            "--keychain",
        ):
            self.assertNotIn(forbidden, command.argv)

    def test_credential_references_are_opaque_and_repr_safe(self) -> None:
        self.assertNotIn("A" * 40, repr(self.credentials))
        self.assertNotIn("runne-notary-01", repr(self.credentials))
        for identity, profile in (
            ("short", "runne-notary-01"),
            ("A" * 40, "--password"),
            ("A" * 40, "contains space"),
            ("A" * 40, "path/profile"),
        ):
            with self.subTest(identity=identity, profile=profile):
                with self.assertRaises(ValueError):
                    ProductionCredentialReferences(identity, profile)

    def test_secret_bearing_credential_options_are_not_command_inputs(self) -> None:
        for forbidden in (
            "--password",
            "--key",
            "--key-id",
            "--issuer",
            "--sync",
            "--keychain",
            "--apple-id",
            "--team-id",
        ):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(ValueError):
                    CommandSpec("forged", "/usr/bin/xcrun", (forbidden, "value"), ".")

    def test_live_boundary_uses_fixed_environment_without_identity_discovery(self) -> None:
        command = build_product_signing_commands(self.candidate, self.credentials)[0]
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
