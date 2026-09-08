"""Independent, exact macOS deployment measurements for production evidence."""
from __future__ import annotations

import plistlib
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from codec import Rejected, file_digest
from contract import DEPLOYMENT, ROLE_PATHS, TEAM

IDENTIFIERS = {"desktop":"com.runne.desktop", "writer":"runne", "daemon":"runned", "service":"com.runne.credential-service"}
ROOT = Path("Contents/Resources/native-enrollment")
ARTIFACTS = {"launch_agent_plist_sha256":Path("Contents/Library/LaunchAgents/com.runne.credential-service.plist"), "entitlements_sha256":ROOT / "credential-service.entitlements.plist", "provisioning_sha256":Path("Contents/Library/Helpers/RunneCredentialService.app/Contents/embedded.provisionprofile"), "protocol_sha256":ROOT / "xpc-protocol-v1.json", "contract_sha256":ROOT / "release-candidate-binding.json"}
LEGACY_KEYCHAIN_SYMBOLS = frozenset({"SecKeychainOpen", "SecKeychainCreate", "SecKeychainDelete", "SecKeychainItemCopyAccess", "SecKeychainItemCreateFromContent", "SecKeychainItemCopyContent", "SecKeychainItemCopyKeychain", "SecKeychainItemModifyAttributesAndData", "SecKeychainSearchCreateFromAttributes"})


def verify_roles(package: Path, tuple_value: object, now: datetime | None = None) -> None:
    if not isinstance(tuple_value, dict): raise Rejected("native tuple is invalid")
    for name, relative in ARTIFACTS.items():
        if tuple_value.get(name) != file_digest(package / relative): raise Rejected("native deployment artifact differs")
    _launch_agent(package / ARTIFACTS["launch_agent_plist_sha256"])
    _profile(package / ARTIFACTS["provisioning_sha256"], "service", now)
    for role, relative in ROLE_PATHS.items():
        target = package / relative
        _identity(_run(["/usr/bin/codesign", "-dvv", str(target)]), role)
        _entitlements(_run(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(target)]), role)
        _notarized(_run(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(target)]))
        _symbols(_run(["/usr/bin/nm", "-u", str(target)]))
    _profile(package / "Contents/embedded.provisionprofile", "desktop", now)


def _identity(output: str, role: str) -> None:
    values = _lines(output); authority = values.get("Authority")
    kind, separator, subject = authority.partition(": ") if isinstance(authority, str) else ("", "", "")
    if kind != "Developer ID Application" or not separator or not subject or values.get("Identifier") != IDENTIFIERS[role] or values.get("TeamIdentifier") != TEAM: raise Rejected("code identity measurement differs")


def _entitlements(output: str, role: str) -> None:
    try: value = plistlib.loads(output[output.index("<plist"):].encode())
    except (ValueError, plistlib.InvalidFileException): raise Rejected("entitlements measurement differs") from None
    if value != DEPLOYMENT["entitlements"][role]: raise Rejected("entitlements measurement differs")


def _profile(path: Path, role: str, now: datetime | None = None) -> None:
    try: value = plistlib.loads(_run(["/usr/bin/security", "cms", "-D", "-i", str(path)]).encode())
    except (ValueError, plistlib.InvalidFileException): raise Rejected("provisioning measurement differs") from None
    expected = {"application-identifier":f"{TEAM}.{IDENTIFIERS[role]}", "com.apple.developer.team-identifier":TEAM, "get-task-allow":False, "keychain-access-groups":[f"{TEAM}.{IDENTIFIERS[role]}"]}
    metadata = {"ApplicationIdentifierPrefix":[TEAM], "Platform":["OSX"], "ProvisionsAllDevices":True, "TeamIdentifier":[TEAM]}
    if not isinstance(value, dict): raise Rejected("provisioning measurement differs")
    dates = value.get("CreationDate"), value.get("ExpirationDate")
    if value.get("Entitlements") != expected or any(value.get(key) != item for key,item in metadata.items()) or value.get("Name") != f"Runne {role.title()} Distribution" or not isinstance(value.get("UUID"), str) or not isinstance(value.get("TimeToLive"), int) or value["TimeToLive"] <= 0 or not isinstance(dates[0], datetime) or not isinstance(dates[1], datetime): raise Rejected("provisioning measurement differs")
    created, expires = (_utc(dates[0]), _utc(dates[1])); observed = _utc(now or datetime.now(timezone.utc))
    if created >= expires or not created <= observed < expires or expires - created > timedelta(days=value["TimeToLive"]): raise Rejected("provisioning measurement differs")


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _launch_agent(path: Path) -> None:
    try: value = plistlib.loads(path.read_bytes())
    except (OSError, ValueError, plistlib.InvalidFileException): raise Rejected("launch agent measurement differs") from None
    expected = {"Label":DEPLOYMENT["launch_agent_label"], "BundleProgram":DEPLOYMENT["bundle_program"], "KeepAlive":False, "RunAtLoad":False, "MachServices":DEPLOYMENT["mach_services"]}
    if value != expected: raise Rejected("launch agent measurement differs")


def _notarized(output: str) -> None:
    values = _lines(output)
    accepted = any(line.strip() == "accepted" or line.endswith(": accepted") for line in output.splitlines())
    if values.get("source") != "Notarized Developer ID" or not accepted: raise Rejected("notarization measurement differs")


def _symbols(output: str) -> None:
    symbols = {line.split()[-1].lstrip("_") for line in output.splitlines() if line.split()}
    if LEGACY_KEYCHAIN_SYMBOLS & symbols: raise Rejected("forbidden native link differs")


def _lines(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator and key and key not in values: values[key] = value
    return values


def _run(command: list[str]) -> str:
    try: result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15, check=False, env={"PATH":"/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired): raise Rejected("native code inspection is unavailable") from None
    if result.returncode != 0: raise Rejected("native code inspection rejected")
    return result.stdout + result.stderr
