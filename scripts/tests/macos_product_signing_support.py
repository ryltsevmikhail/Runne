import json
import plistlib
import tempfile
from pathlib import Path

from scripts.macos_signing.product_models import ProductCandidateRequest
from scripts.macos.validate_credential_service_package import (
    BUNDLE_PROGRAM,
    ENDPOINTS,
    ENTITLEMENTS_BYTES,
    XPC_PROTOCOL_BYTES,
)
from scripts.macos_signing.product_entitlements import (
    CREDENTIAL_SERVICE_ENTITLEMENTS,
    PRODUCT_APP_ENTITLEMENTS,
)
from scripts.macos_signing.product_validation import validate_product_candidate


def validated_product_candidate():
    temporary_directory, root, _, validated = product_candidate_fixture()
    return temporary_directory, root, validated


def product_candidate_fixture():
    temporary_directory = tempfile.TemporaryDirectory()
    root = Path(temporary_directory.name)
    candidate = root / "Runne.app"
    macos = candidate / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    (candidate / "Contents" / "Resources").mkdir()
    for name, value in (
        ("runne-desktop", b"main executable\n"),
        ("runne", b"cli executable\n"),
        ("runned", b"daemon executable\n"),
    ):
        target = macos / name
        target.write_bytes(value)
        target.chmod(0o755)
    (candidate / "Contents" / "Info.plist").write_bytes(
        plistlib.dumps({"CFBundleExecutable": "runne-desktop"})
    )
    (candidate / "Contents" / "embedded.provisionprofile").write_bytes(
        b"developer-id-profile\n"
    )
    add_credential_service_fixture(candidate)
    entitlements = []
    for role in ("app", "cli", "daemon", "credential-service"):
        path = root / f"{role}.plist"
        payload = {
            "app": PRODUCT_APP_ENTITLEMENTS,
            "credential-service": CREDENTIAL_SERVICE_ENTITLEMENTS,
        }.get(role, {})
        path.write_bytes(plistlib.dumps(payload))
        entitlements.append(path)
    request = ProductCandidateRequest(
        candidate,
        "a" * 64,
        entitlements[0],
        entitlements[1],
        entitlements[2],
        entitlements[3],
    )
    return temporary_directory, root, request, validate_product_candidate(request)


def add_credential_service_fixture(candidate: Path) -> None:
    contents = candidate / "Contents"
    helper_contents = contents / "Library/Helpers/RunneCredentialService.app/Contents"
    macos = helper_contents / "MacOS"
    launch_agents = contents / "Library/LaunchAgents"
    native = contents / "Resources/native-enrollment"
    macos.mkdir(parents=True)
    launch_agents.mkdir(parents=True)
    native.mkdir(parents=True, exist_ok=True)
    executable = macos / "runne-credential-service"
    executable.write_bytes(b"credential service executable\n")
    executable.chmod(0o755)
    (helper_contents / "embedded.provisionprofile").write_bytes(b"service profile\n")
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
    (launch_agents / "com.runne.credential-service.plist").write_bytes(
        plistlib.dumps({
            "Label": "com.runne.credential-service",
            "BundleProgram": BUNDLE_PROGRAM,
            "KeepAlive": False,
            "RunAtLoad": False,
            "MachServices": dict.fromkeys(ENDPOINTS, True),
        })
    )
    (native / "credential-service.entitlements.plist").write_bytes(
        ENTITLEMENTS_BYTES
    )
    (native / "xpc-protocol-v1.json").write_bytes(XPC_PROTOCOL_BYTES)
    binding = {
        "arch": "arm64",
        "platform": "macos",
        "productId": "com.runne.desktop",
        "profileId": "gocode-ui-client/2",
        "releaseCandidateSha256": "a" * 64,
        "schemaVersion": 1,
        "version": "0.0.3",
    }
    (native / "release-candidate-binding.json").write_text(
        json.dumps(binding, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
