import plistlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.macos_signing.models import FailureCode
from scripts.macos_signing.product_models import ProductCandidateRequest
from scripts.macos_signing.product_validation import (
    revalidate_product_candidate,
    validate_product_candidate,
)


class MacOSProductSigningCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.candidate = self.root / "Runne.app"
        macos = self.candidate / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        (self.candidate / "Contents" / "Resources").mkdir()
        for name, value in (
            ("runne-desktop", b"main executable\n"),
            ("runne", b"cli executable\n"),
            ("runned", b"daemon executable\n"),
        ):
            target = macos / name
            target.write_bytes(value)
            target.chmod(0o755)
        (self.candidate / "Contents" / "Info.plist").write_bytes(
            plistlib.dumps({"CFBundleExecutable": "runne-desktop"})
        )
        (self.candidate / "Contents" / "embedded.provisionprofile").write_bytes(
            b"developer-id-profile\n"
        )
        (self.candidate / "Contents" / "Resources" / "asset.txt").write_text(
            "asset\n"
        )
        self.entitlements = {}
        for role in ("app", "cli", "daemon"):
            path = self.root / f"{role}.plist"
            payload = (
                {
                    "com.apple.application-identifier": "758F9Z45SR.com.runne.desktop",
                    "com.apple.developer.team-identifier": "758F9Z45SR",
                    "keychain-access-groups": ["758F9Z45SR.com.runne.desktop"],
                }
                if role == "app"
                else {}
            )
            path.write_bytes(plistlib.dumps(payload))
            self.entitlements[role] = path

    def request(self) -> ProductCandidateRequest:
        return ProductCandidateRequest(
            candidate_app=self.candidate,
            release_candidate_sha256="a" * 64,
            app_entitlements=self.entitlements["app"],
            cli_entitlements=self.entitlements["cli"],
            daemon_entitlements=self.entitlements["daemon"],
        )

    def test_product_app_entitlements_authorize_private_data_protection_group(self) -> None:
        self.entitlements["app"].write_bytes(
            plistlib.dumps(
                {
                    "com.apple.application-identifier": "758F9Z45SR.com.runne.desktop",
                    "com.apple.developer.team-identifier": "758F9Z45SR",
                    "keychain-access-groups": ["758F9Z45SR.com.runne.desktop"],
                }
            )
        )

        validated = validate_product_candidate(self.request())

        self.assertFalse(hasattr(validated, "code"))

    def test_empty_product_app_entitlements_are_rejected(self) -> None:
        self.entitlements["app"].write_bytes(plistlib.dumps({}))
        failure = validate_product_candidate(self.request())

        self.assertEqual(
            getattr(failure, "code", None),
            FailureCode.ENTITLEMENTS_MISMATCH,
        )

    def test_exact_three_component_bundle_is_captured(self) -> None:
        validated = validate_product_candidate(self.request())

        self.assertEqual(validated.candidate.relative_name, "Runne.app")
        self.assertEqual(validated.main.relative_path, "Contents/MacOS/runne-desktop")
        self.assertEqual(validated.cli.relative_path, "Contents/MacOS/runne")
        self.assertEqual(validated.daemon.relative_path, "Contents/MacOS/runned")
        self.assertEqual(len({validated.main.sha256, validated.cli.sha256, validated.daemon.sha256}), 3)
        self.assertEqual(
            len(
                {
                    (validated.app_entitlements.device, validated.app_entitlements.inode),
                    (validated.cli_entitlements.device, validated.cli_entitlements.inode),
                    (validated.daemon_entitlements.device, validated.daemon_entitlements.inode),
                }
            ),
            3,
        )

    def test_malformed_release_digest_fails_closed(self) -> None:
        for value in (None, 1, "A" * 64, "short"):
            with self.subTest(value=value):
                failure = validate_product_candidate(
                    replace(self.request(), release_candidate_sha256=value)
                )
                self.assertEqual(failure.code, FailureCode.ARTIFACT_NOT_FOUND)

    def test_non_exact_component_layout_is_rejected(self) -> None:
        for mutation in ("missing", "extra", "not-executable"):
            with self.subTest(mutation=mutation):
                with self._fresh_fixture():
                    macos = self.candidate / "Contents" / "MacOS"
                    if mutation == "missing":
                        (macos / "runne").unlink()
                    elif mutation == "extra":
                        extra = macos / "extra"
                        extra.write_text("unexpected\n")
                        extra.chmod(0o755)
                    else:
                        (macos / "runned").chmod(0o644)
                    failure = validate_product_candidate(self.request())
                    self.assertEqual(failure.code, FailureCode.ARTIFACT_NOT_FOUND)

    def test_missing_embedded_distribution_profile_is_rejected(self) -> None:
        (self.candidate / "Contents" / "embedded.provisionprofile").unlink()

        failure = validate_product_candidate(self.request())

        self.assertEqual(
            getattr(failure, "code", None),
            FailureCode.ENTITLEMENTS_MISMATCH,
        )

    def test_symlinked_component_and_reused_entitlement_inode_are_rejected(self) -> None:
        macos = self.candidate / "Contents" / "MacOS"
        cli = macos / "runne"
        cli.unlink()
        cli.symlink_to(macos / "runned")
        failure = validate_product_candidate(self.request())
        self.assertEqual(failure.code, FailureCode.ARTIFACT_NOT_FOUND)

        with self._fresh_fixture():
            request = replace(
                self.request(),
                cli_entitlements=self.entitlements["app"],
            )
            failure = validate_product_candidate(request)
            self.assertEqual(failure.code, FailureCode.ENTITLEMENTS_MISMATCH)

    def test_any_bundle_or_entitlement_mutation_invalidates_snapshot(self) -> None:
        for relative in (
            "Contents/MacOS/runne-desktop",
            "Contents/MacOS/runne",
            "Contents/MacOS/runned",
            "Contents/Resources/asset.txt",
        ):
            with self.subTest(relative=relative):
                with self._fresh_fixture():
                    captured = validate_product_candidate(self.request())
                    (self.candidate / relative).write_bytes(b"mutated\n")
                    failure = revalidate_product_candidate(self.candidate, captured)
                    self.assertEqual(failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)
        with self._fresh_fixture():
            captured = validate_product_candidate(self.request())
            self.entitlements["cli"].write_bytes(plistlib.dumps({"changed": True}))
            failure = revalidate_product_candidate(self.candidate, captured)
            self.assertEqual(failure.code, FailureCode.ARTIFACT_IDENTITY_MISMATCH)

    def _fresh_fixture(self):
        testcase = self

        class FreshFixture:
            def __enter__(self):
                testcase.setUp()

            def __exit__(self, *_args):
                return None

        return FreshFixture()


if __name__ == "__main__":
    unittest.main()
