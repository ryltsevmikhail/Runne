import plistlib
import tempfile
from pathlib import Path

from scripts.macos_signing.product_models import ProductCandidateRequest
from scripts.macos_signing.product_entitlements import PRODUCT_APP_ENTITLEMENTS
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
    entitlements = []
    for role in ("app", "cli", "daemon"):
        path = root / f"{role}.plist"
        payload = PRODUCT_APP_ENTITLEMENTS if role == "app" else {}
        path.write_bytes(plistlib.dumps(payload))
        entitlements.append(path)
    request = ProductCandidateRequest(
        candidate,
        "a" * 64,
        entitlements[0],
        entitlements[1],
        entitlements[2],
    )
    return temporary_directory, root, request, validate_product_candidate(request)
