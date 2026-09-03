import json
import plistlib
import tempfile
import unittest
from pathlib import Path

from scripts.macos.validate_credential_service_package import (
    BUNDLE_PROGRAM,
    ENDPOINTS,
    ENTITLEMENTS_BYTES,
    XPC_PROTOCOL_BYTES,
    validate_credential_service_package,
)


class CredentialServicePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.app = Path(temporary.name) / "Runne.app"
        contents = self.app / "Contents"
        helper_contents = contents / "Library/Helpers/RunneCredentialService.app/Contents"
        macos = helper_contents / "MacOS"
        launch_agents = contents / "Library/LaunchAgents"
        native = contents / "Resources/native-enrollment"
        macos.mkdir(parents=True)
        launch_agents.mkdir(parents=True)
        native.mkdir(parents=True)
        executable = macos / "runne-credential-service"
        executable.write_bytes(b"service")
        executable.chmod(0o755)
        (helper_contents / "embedded.provisionprofile").write_bytes(b"profile")
        (helper_contents / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleDevelopmentRegion": "en",
            "CFBundleExecutable": "runne-credential-service",
            "CFBundleIdentifier": "com.runne.credential-service",
            "CFBundleInfoDictionaryVersion": "6.0",
            "CFBundleName": "RunneCredentialService",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "0.0.3",
            "CFBundleVersion": "0.0.3",
            "LSBackgroundOnly": True,
            "LSMinimumSystemVersion": "13.0",
        }))
        self.launch_agent = launch_agents / "com.runne.credential-service.plist"
        self.launch_agent.write_bytes(plistlib.dumps({
            "Label": "com.runne.credential-service",
            "BundleProgram": BUNDLE_PROGRAM,
            "KeepAlive": False,
            "RunAtLoad": False,
            "MachServices": dict.fromkeys(ENDPOINTS, True),
        }))
        (native / "credential-service.entitlements.plist").write_bytes(
            ENTITLEMENTS_BYTES
        )
        (native / "xpc-protocol-v1.json").write_bytes(XPC_PROTOCOL_BYTES)
        self.binding = native / "release-candidate-binding.json"
        self.binding.write_text(
            json.dumps(
                {
                    "arch": "arm64",
                    "platform": "macos",
                    "productId": "com.runne.desktop",
                    "profileId": "gocode-ui-client/2",
                    "releaseCandidateSha256": "a" * 64,
                    "schemaVersion": 1,
                    "version": "0.0.3",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

    def test_exact_helper_and_launch_agent_are_accepted(self) -> None:
        package = validate_credential_service_package(self.app)
        self.assertIsNotNone(package)
        self.assertEqual(package.executable.name, "runne-credential-service")
        self.assertEqual(package.release_candidate_sha256, "a" * 64)

    def test_missing_profile_or_altered_endpoint_is_rejected(self) -> None:
        helper = self.app / "Contents/Library/Helpers/RunneCredentialService.app/Contents"
        (helper / "embedded.provisionprofile").unlink()
        self.assertIsNone(validate_credential_service_package(self.app))
        (helper / "embedded.provisionprofile").write_bytes(b"profile")
        payload = plistlib.loads(self.launch_agent.read_bytes())
        payload["MachServices"]["com.runne.credential-service.extra.v1"] = True
        self.launch_agent.write_bytes(plistlib.dumps(payload))
        self.assertIsNone(validate_credential_service_package(self.app))

    def test_symlink_or_extra_helper_executable_is_rejected(self) -> None:
        macos = self.app / "Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS"
        extra = macos / "extra"
        extra.write_bytes(b"extra")
        extra.chmod(0o755)
        self.assertIsNone(validate_credential_service_package(self.app))

    def test_missing_or_noncanonical_tuple_resource_is_rejected(self) -> None:
        protocol = self.app / "Contents/Resources/native-enrollment/xpc-protocol-v1.json"
        protocol.unlink()
        self.assertIsNone(validate_credential_service_package(self.app))
        protocol.write_bytes(XPC_PROTOCOL_BYTES)
        self.binding.write_bytes(self.binding.read_bytes() + b"\n")
        self.assertIsNone(validate_credential_service_package(self.app))


if __name__ == "__main__":
    unittest.main()
