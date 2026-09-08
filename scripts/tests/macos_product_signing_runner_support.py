import plistlib
import shutil
from datetime import datetime
from pathlib import Path

from scripts.macos_signing.models import CommandResult

_TEAM_ID = "758F9Z45SR"


class ProductRecordingRunner:
    def __init__(
        self,
        root: Path,
        failure_phase: str | None = None,
        mutate: bool = True,
        empty_app_entitlements: bool = False,
        invalid_profile: bool = False,
        invalid_service_profile: bool = False,
        invalid_requirement_role: str | None = None,
    ) -> None:
        self.root = root
        self.failure_phase = failure_phase
        self.mutate = mutate
        self.empty_app_entitlements = empty_app_entitlements
        self.invalid_profile = invalid_profile
        self.invalid_service_profile = invalid_service_profile
        self.invalid_requirement_role = invalid_requirement_role
        self.commands = []

    def run(self, command):
        self.commands.append(command)
        if command.phase == self.failure_phase:
            return CommandResult(1, "SYNTHETIC-RAW-MARKER", "UNKNOWN_STATUS")
        if self.mutate:
            self._apply_side_effect(command.phase)
        return self._success(command.phase)

    def _apply_side_effect(self, phase: str) -> None:
        macos = self.root / "Runne.app" / "Contents" / "MacOS"
        if phase == "sign-daemon":
            (macos / "runned").write_bytes(b"signed daemon\n")
        elif phase == "sign-credential-service":
            helper = (
                self.root
                / "Runne.app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service"
            )
            helper.write_bytes(b"signed credential service\n")
        elif phase == "sign-cli":
            (macos / "runne").write_bytes(b"signed cli\n")
        elif phase == "sign-app":
            (macos / "runne-desktop").write_bytes(b"signed app\n")
        elif phase == "package-app-zip":
            (self.root / ".runne-product-work" / "app.zip").write_bytes(
                b"signed app zip\n"
            )
        elif phase == "staple-app":
            ticket = self.root / "Runne.app" / "Contents" / "_CodeSignature" / "ticket"
            ticket.parent.mkdir(exist_ok=True)
            ticket.write_bytes(b"ticket\n")
        elif phase == "create-dmg":
            (self.root / ".runne-product-work" / "Runne.dmg").write_bytes(b"dmg\n")
        elif phase == "stage-dmg-app":
            shutil.copytree(
                self.root / "Runne.app",
                self.root / ".runne-product-work" / "dmg-root" / "Runne.app",
            )
        elif phase == "sign-dmg":
            (self.root / ".runne-product-work" / "Runne.dmg").write_bytes(
                b"signed dmg\n"
            )
        elif phase == "staple-dmg":
            (self.root / ".runne-product-work" / "Runne.dmg").write_bytes(
                b"stapled dmg\n"
            )

    def _success(self, phase: str) -> CommandResult:
        if phase.startswith("inspect-provisioning-profile-"):
            return self._profile_result(
                phase.removeprefix("inspect-provisioning-profile-")
            )
        if phase.startswith("metadata-"):
            return self._metadata_result(phase.removeprefix("metadata-"))
        if phase.startswith("requirement-"):
            role = phase.removeprefix("requirement-")
            identifier = {
                "app": "com.runne.desktop",
                "cli": "runne",
                "daemon": "runned",
                "credential-service": "com.runne.credential-service",
            }[role]
            if role == self.invalid_requirement_role:
                identifier = "example.invalid"
            rendered_identifier = (
                identifier if role in ("cli", "daemon") else f'"{identifier}"'
            )
            return CommandResult(
                0,
                "",
                f"designated => identifier {rendered_identifier} and anchor apple generic",
            )
        if phase.startswith("entitlements-"):
            payload = self._entitlement_payload(phase)
            return CommandResult(0, plistlib.dumps(payload).decode(), "")
        if phase.startswith("notary-"):
            return CommandResult(0, '{"status":"Accepted"}', "")
        return CommandResult(0, "", "")

    def _profile_result(self, role: str) -> CommandResult:
        expected = {
            "app": "758F9Z45SR.com.runne.desktop",
            "credential-service": "758F9Z45SR.com.runne.credential-service",
        }[role]
        application_identifier = (
            "758F9Z45SR.example.invalid"
            if self.invalid_profile
            or (role == "credential-service" and self.invalid_service_profile)
            else expected
        )
        payload = {
            "TeamIdentifier": [_TEAM_ID],
            "ProvisionsAllDevices": True,
            "ExpirationDate": datetime(2035, 1, 1),
            "Entitlements": {
                "com.apple.application-identifier": application_identifier,
                "com.apple.developer.team-identifier": _TEAM_ID,
                "keychain-access-groups": [f"{_TEAM_ID}.*"],
            },
        }
        return CommandResult(0, plistlib.dumps(payload).decode(), "")

    def _metadata_result(self, role: str) -> CommandResult:
        identifier = {
            "app": "com.runne.desktop",
            "cli": "runne",
            "daemon": "runned",
            "credential-service": "com.runne.credential-service",
        }[role]
        lines = (
            f"Identifier={identifier}",
            f"TeamIdentifier={_TEAM_ID}",
            "Authority=Developer ID Application: Synthetic",
            "CDHash=" + "a" * 40,
            "CodeDirectory v=20500 flags=0x10000(runtime)",
        )
        return CommandResult(0, "", "\n".join(lines))

    def _entitlement_payload(self, phase: str) -> dict:
        role = phase.removeprefix("entitlements-")
        if role in ("cli", "daemon") or (role == "app" and self.empty_app_entitlements):
            return {}
        identifier = {
            "app": "758F9Z45SR.com.runne.desktop",
            "credential-service": "758F9Z45SR.com.runne.credential-service",
        }[role]
        return {
            "com.apple.application-identifier": identifier,
            "com.apple.developer.team-identifier": _TEAM_ID,
            "keychain-access-groups": [identifier],
        }
