#!/usr/bin/env python3
"""Validate the exact bundled macOS credential-service layout."""

from __future__ import annotations

import argparse
import json
import plistlib
import re
import stat
from dataclasses import dataclass
from pathlib import Path

LABEL = "com.runne.credential-service"
HELPER_RELATIVE = Path("Contents/Library/Helpers/RunneCredentialService.app")
LAUNCH_AGENT_RELATIVE = Path(
    "Contents/Library/LaunchAgents/com.runne.credential-service.plist"
)
EXECUTABLE_RELATIVE = Path("Contents/MacOS/runne-credential-service")
ENDPOINTS = (
    "com.runne.credential-service.desktop.v1",
    "com.runne.credential-service.runtime.v1",
    "com.runne.credential-service.writer.v1",
)
BUNDLE_PROGRAM = str(HELPER_RELATIVE / EXECUTABLE_RELATIVE)
NATIVE_ENROLLMENT_RELATIVE = Path("Contents/Resources/native-enrollment")
ENTITLEMENTS_BYTES = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key>
  <string>758F9Z45SR.com.runne.credential-service</string>
  <key>com.apple.developer.team-identifier</key>
  <string>758F9Z45SR</string>
  <key>keychain-access-groups</key>
  <array>
    <string>758F9Z45SR.com.runne.credential-service</string>
  </array>
</dict>
</plist>
"""
XPC_PROTOCOL_BYTES = b'{"schemaVersion":1,"transport":"nsxpc","compatibilityBundles":[{"registrationWire":1,"registrationAuthSuite":1,"providerFrameWire":2,"providerGrantAuth":1,"runtimeEnvelopeWire":2,"runtimeRequestAuth":3,"runtimeReplyAuth":3}]}'
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class CredentialServicePackage:
    helper: Path
    executable: Path
    info_plist: Path
    provisioning_profile: Path
    launch_agent_plist: Path
    entitlements: Path
    xpc_protocol: Path
    release_candidate_binding: Path
    release_candidate_sha256: str


def validate_credential_service_package(
    candidate_app: Path,
) -> CredentialServicePackage | None:
    if not _directory(candidate_app) or candidate_app.suffix != ".app":
        return None
    helper = candidate_app / HELPER_RELATIVE
    contents = helper / "Contents"
    macos = contents / "MacOS"
    executable = helper / EXECUTABLE_RELATIVE
    info = contents / "Info.plist"
    profile = contents / "embedded.provisionprofile"
    launch_agent = candidate_app / LAUNCH_AGENT_RELATIVE
    resources = candidate_app / NATIVE_ENROLLMENT_RELATIVE
    entitlements = resources / "credential-service.entitlements.plist"
    protocol = resources / "xpc-protocol-v1.json"
    candidate = resources / "release-candidate-binding.json"
    if not all(_directory(path) for path in (helper, contents, macos)):
        return None
    if not _exact_entries(macos, {executable}) or not _executable(executable):
        return None
    if not all(
        _file(path)
        for path in (info, profile, launch_agent, entitlements, protocol, candidate)
    ):
        return None
    if not _helper_info_is_exact(info) or not _launch_agent_is_exact(launch_agent):
        return None
    release_candidate = _release_candidate(candidate)
    if (
        _bytes(entitlements) != ENTITLEMENTS_BYTES
        or _bytes(protocol) != XPC_PROTOCOL_BYTES
        or release_candidate is None
    ):
        return None
    return CredentialServicePackage(
        helper,
        executable,
        info,
        profile,
        launch_agent,
        entitlements,
        protocol,
        candidate,
        release_candidate,
    )


def _helper_info_is_exact(path: Path) -> bool:
    expected = {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleExecutable": "runne-credential-service",
        "CFBundleIdentifier": LABEL,
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "RunneCredentialService",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "0.0.3",
        "CFBundleVersion": "0.0.3",
        "LSBackgroundOnly": True,
        "LSMinimumSystemVersion": "13.0",
    }
    return _plist(path) == expected


def _launch_agent_is_exact(path: Path) -> bool:
    expected = {
        "Label": LABEL,
        "BundleProgram": BUNDLE_PROGRAM,
        "KeepAlive": False,
        "RunAtLoad": False,
        "MachServices": dict.fromkeys(ENDPOINTS, True),
    }
    return _plist(path) == expected


def _plist(path: Path) -> object:
    try:
        return plistlib.loads(path.read_bytes())
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None


def _release_candidate(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
        pairs = json.loads(raw, object_pairs_hook=_unique_object)
        canonical = json.dumps(
            pairs,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return None
    if type(pairs) is not dict:
        return None
    expected = {
        "arch",
        "platform",
        "productId",
        "profileId",
        "releaseCandidateSha256",
        "schemaVersion",
        "version",
    }
    digest = pairs.get("releaseCandidateSha256")
    if (
        set(pairs) != expected
        or raw != canonical
        or pairs.get("schemaVersion") != 1
        or pairs.get("productId") != "com.runne.desktop"
        or pairs.get("platform") != "macos"
        or pairs.get("arch") not in ("arm64", "x86_64")
        or pairs.get("profileId") != "gocode-ui-client/2"
        or not isinstance(pairs.get("version"), str)
        or not pairs["version"]
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
    ):
        return None
    return digest


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _exact_entries(path: Path, expected: set[Path]) -> bool:
    try:
        return set(path.iterdir()) == expected
    except (OSError, ValueError):
        return False


def _directory(path: Path) -> bool:
    try:
        return not path.is_symlink() and path.is_dir()
    except (OSError, ValueError):
        return False


def _file(path: Path) -> bool:
    try:
        return not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode)
    except (OSError, ValueError):
        return False


def _executable(path: Path) -> bool:
    try:
        return _file(path) and bool(path.stat().st_mode & 0o111)
    except (OSError, ValueError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--candidate-app", required=True, type=Path)
    package = validate_credential_service_package(parser.parse_args().candidate_app)
    print(json.dumps({"valid": package is not None}, sort_keys=True))
    return 0 if package is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
