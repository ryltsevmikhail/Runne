import contextlib
import io
import json
import unittest
from unittest import mock

from scripts.macos_signing.models import FailureCode, SigningFailure
from scripts.macos_signing.product_cli import main
from scripts.macos_signing.product_models import (
    ProductSigningOutcome,
    ProductSigningStage,
)


class MacOSProductSigningCliTests(unittest.TestCase):
    def test_cli_emits_only_redacted_typed_outcome(self) -> None:
        identity = "A" * 40
        profile = "runne-notary-01"
        stdout, stderr = io.StringIO(), io.StringIO()
        outcome = ProductSigningOutcome(
            ProductSigningStage.UNSIGNED_APP,
            SigningFailure(FailureCode.SIGNING_IDENTITY_UNAVAILABLE, "sign-daemon", ""),
            None,
        )
        argv = [
            "--candidate-app",
            "Runne.app",
            "--output-dmg",
            "Runne.dmg",
            "--evidence",
            "Runne-signing-evidence.v2.json",
            "--release-candidate-sha256",
            "a" * 64,
            "--signing-identity-ref",
            identity,
            "--notary-profile-ref",
            profile,
            "--notary-keychain-ref",
            "/tmp/runne-release.keychain",
        ]
        with (
            mock.patch(
                "scripts.macos_signing.product_cli.run_product_signing",
                return_value=outcome,
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = main(argv)

        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr.getvalue(), "")
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["failure"]["code"], "SIGNING_IDENTITY_UNAVAILABLE")
        self.assertNotIn(identity, stdout.getvalue())
        self.assertNotIn(profile, stdout.getvalue())

    def test_secret_bearing_options_are_not_part_of_cli(self) -> None:
        for option in ("--password", "--apple-id", "--team-id", "--key", "--issuer"):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                main([option, "secret"])
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
