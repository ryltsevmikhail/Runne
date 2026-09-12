"""Independent, exact macOS deployment measurements for production evidence."""
from __future__ import annotations

import plistlib
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from xml.parsers.expat import ExpatError

from codec import Rejected, file_digest
from contract import DEPLOYMENT, ROLE_PATHS, TEAM
from profile_grants import validate as validate_profile_grant

IDENTIFIERS = {"desktop":"com.runne.desktop", "writer":"runne", "daemon":"runned", "service":"com.runne.credential-service"}
ROOT = Path("Contents/Resources/native-enrollment")
ARTIFACTS = {"launch_agent_plist_sha256":Path("Contents/Library/LaunchAgents/com.runne.credential-service.plist"), "entitlements_sha256":ROOT / "credential-service.entitlements.plist", "provisioning_sha256":Path("Contents/Library/Helpers/RunneCredentialService.app/Contents/embedded.provisionprofile"), "protocol_sha256":ROOT / "xpc-protocol-v1.json", "contract_sha256":Path("Contents/Resources/contracts/gocode-ui-client-2/bundle.json")}
LEGACY_KEYCHAIN_SYMBOLS = frozenset({"SecKeychainOpen", "SecKeychainCreate", "SecKeychainDelete", "SecKeychainItemCopyAccess", "SecKeychainItemCreateFromContent", "SecKeychainItemCopyContent", "SecKeychainItemCopyKeychain", "SecKeychainItemModifyAttributesAndData", "SecKeychainSearchCreateFromAttributes"})


@dataclass(frozen=True)
class CommandOutput:
    stdout: str
    stderr: str

    def combined(self) -> str:
        return self.stdout + self.stderr


def verify_roles(package: Path, tuple_value: object, code_identities: object,
                 now: datetime | None = None) -> None:
    if not isinstance(tuple_value, dict): raise Rejected("native tuple is invalid")
    identities = _identities(code_identities)
    for name, relative in ARTIFACTS.items():
        if tuple_value.get(name) != file_digest(package / relative): raise Rejected("native deployment artifact differs")
    _launch_agent(package / ARTIFACTS["launch_agent_plist_sha256"])
    _profile(package / ARTIFACTS["provisioning_sha256"], "service", now)
    for role, relative in ROLE_PATHS.items():
        target = package / relative
        _verify_code(target, identities[role])
        _identity(_run(["/usr/bin/codesign", "--display", "--verbose=4", "--", str(target)]).combined(), role, identities[role])
        _entitlements(_run(["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", "--", str(target)]).stdout, role)
        _notarized(_run(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(target)]).combined())
        _symbols(_run(["/usr/bin/nm", "-u", str(target)]).combined())
    _profile(package / "Contents/embedded.provisionprofile", "desktop", now)


def _identities(value: object) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or set(value) != set(IDENTIFIERS):
        raise Rejected("code identity measurement differs")
    identities: dict[str, dict[str, str]] = {}
    for role, identifier in IDENTIFIERS.items():
        identity = value.get(role)
        if not isinstance(identity, dict) or set(identity) != {"identifier", "teamIdentifier", "cdhash"} or identity.get("identifier") != identifier or identity.get("teamIdentifier") != TEAM or not isinstance(identity.get("cdhash"), str) or re.fullmatch(r"[0-9a-f]{40}", identity["cdhash"]) is None:
            raise Rejected("code identity measurement differs")
        identities[role] = identity
    return identities


def _verify_code(path: Path, identity: dict[str, str]) -> None:
    requirement = (
        f'identifier "{identity["identifier"]}" and anchor apple generic and '
        f'certificate leaf[subject.OU] = "{identity["teamIdentifier"]}" and '
        f'cdhash H"{identity["cdhash"]}"'
    )
    _run(["/usr/bin/codesign", "-v", "--strict", f"-R={requirement}", "--", str(path)])


def _identity(output: str, role: str, expected: dict[str, str]) -> None:
    authority = _lines(output).get("Authority")
    kind, separator, subject = authority.partition(": ") if isinstance(authority, str) else ("", "", "")
    observed = {
        "identifier": _exact_line(output, "Identifier="),
        "teamIdentifier": _exact_line(output, "TeamIdentifier="),
        "cdhash": _exact_line(output, "CDHash=").lower(),
    }
    if kind != "Developer ID Application" or not separator or not subject or observed != expected or expected["identifier"] != IDENTIFIERS[role]:
        raise Rejected("code identity measurement differs")


def _exact_line(output: str, prefix: str) -> str:
    values = [line.removeprefix(prefix) for line in output.splitlines() if line.startswith(prefix)]
    if len(values) != 1 or not values[0]: raise Rejected("code identity measurement differs")
    return values[0]


def _entitlements(output: str, role: str) -> None:
    if DEPLOYMENT["entitlements"][role] == {} and output == "":
        return
    try: value = plistlib.loads(output[output.index("<plist"):].encode())
    except (ExpatError, ValueError, plistlib.InvalidFileException): raise Rejected("entitlements measurement differs") from None
    if value != DEPLOYMENT["entitlements"][role]: raise Rejected("entitlements measurement differs")


def _profile(path: Path, role: str, now: datetime | None = None) -> None:
    try: value = plistlib.loads(_run(["/usr/bin/security", "cms", "-D", "-i", str(path)]).stdout.encode())
    except (ExpatError, ValueError, plistlib.InvalidFileException): raise Rejected("provisioning measurement differs") from None
    validate_profile_grant(value, f"{TEAM}.{IDENTIFIERS[role]}", DEPLOYMENT["entitlements"][role], TEAM, now)


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


def _run(command: list[str]) -> CommandOutput:
    try: result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15, check=False, env={"PATH":"/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired): raise Rejected("native code inspection is unavailable") from None
    if result.returncode != 0: raise Rejected("native code inspection rejected")
    return CommandOutput(result.stdout, result.stderr)
