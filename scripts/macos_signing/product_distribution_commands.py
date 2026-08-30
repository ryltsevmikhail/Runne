from pathlib import Path

from .command_grammar import CODESIGN, XCRUN
from .models import CommandSpec
from .product_layout import (
    APP_ZIP_RELATIVE,
    DMG_RELATIVE,
    DMG_ROOT_RELATIVE,
    staged_app_relative,
)
from .product_models import (
    ExternalCommandTemplate,
    ProductionCredentialReferences,
    ProductValidatedCandidate,
)

_DITTO = "/usr/bin/ditto"
_HDIUTIL = "/usr/bin/hdiutil"


def build_product_notary_submit_command(
    relative_zip: str,
    credentials: ProductionCredentialReferences,
) -> CommandSpec:
    _artifact_path(relative_zip, ".zip")
    if not isinstance(credentials, ProductionCredentialReferences):
        raise ValueError("invalid notarization input")
    return _notary_command("notary-app-submit", relative_zip, credentials)


def build_product_distribution_commands(
    candidate: ProductValidatedCandidate,
    credentials: ProductionCredentialReferences,
    relative_zip: str,
    relative_dmg: str,
) -> tuple[CommandSpec, ...]:
    if not isinstance(candidate, ProductValidatedCandidate) or not isinstance(
        credentials, ProductionCredentialReferences
    ):
        raise ValueError("invalid product distribution input")
    if relative_zip != APP_ZIP_RELATIVE or relative_dmg != DMG_RELATIVE:
        raise ValueError("noncanonical product distribution path")
    return _distribution_specs(candidate.candidate.relative_name, credentials)


def redact_distribution_command(
    command: CommandSpec,
) -> ExternalCommandTemplate | None:
    if _product_notary_command_is_exact(command):
        argv = list(command.argv)
        argv[4] = "<NOTARY_PROFILE_REF>"
        argv[6] = "<NOTARY_KEYCHAIN_REF>"
        return ExternalCommandTemplate(command.phase, command.program, tuple(argv))
    if not _distribution_command_is_exact(command):
        return None
    argv = list(command.argv)
    if command.phase == "sign-dmg":
        argv[2] = "<SIGNING_IDENTITY_REF>"
    return ExternalCommandTemplate(command.phase, command.program, tuple(argv))


def canonical_distribution_templates(app_name: str) -> tuple[ExternalCommandTemplate, ...]:
    credentials = ProductionCredentialReferences(
        "A" * 40,
        "opaque-profile",
        Path("/opaque/notary.keychain"),
    )
    return tuple(
        redact_distribution_command(command)
        for command in _distribution_specs(app_name, credentials)
    )


def _distribution_specs(
    app: str,
    credentials: ProductionCredentialReferences,
) -> tuple[CommandSpec, ...]:
    staged_app = staged_app_relative(app)
    return (
        CommandSpec(
            "package-app-zip",
            _DITTO,
            ("-c", "-k", "--keepParent", "--sequesterRsrc", app, APP_ZIP_RELATIVE),
            ".",
        ),
        _notary_command("notary-app-submit", APP_ZIP_RELATIVE, credentials),
        CommandSpec("staple-app", XCRUN, ("stapler", "staple", app), "."),
        CommandSpec("validate-app", XCRUN, ("stapler", "validate", app), "."),
        CommandSpec(
            "gatekeeper-app",
            "/usr/sbin/spctl",
            ("--assess", "--type", "execute", app),
            ".",
        ),
        CommandSpec("stage-dmg-app", _DITTO, (app, staged_app), "."),
        CommandSpec(
            "create-dmg",
            _HDIUTIL,
            (
                "create",
                "-volname",
                "Runne",
                "-srcfolder",
                DMG_ROOT_RELATIVE,
                "-format",
                "UDZO",
                DMG_RELATIVE,
            ),
            ".",
        ),
        CommandSpec(
            "sign-dmg",
            CODESIGN,
            (
                "--force",
                "--sign",
                credentials.signing_identity_ref,
                "--timestamp",
                DMG_RELATIVE,
            ),
            ".",
        ),
        CommandSpec("verify-dmg", CODESIGN, ("--verify", "--strict", DMG_RELATIVE), "."),
        _notary_command("notary-dmg-submit", DMG_RELATIVE, credentials),
        CommandSpec("staple-dmg", XCRUN, ("stapler", "staple", DMG_RELATIVE), "."),
        CommandSpec("validate-dmg", XCRUN, ("stapler", "validate", DMG_RELATIVE), "."),
    )


def _notary_command(
    phase: str,
    artifact: str,
    credentials: ProductionCredentialReferences,
) -> CommandSpec:
    return CommandSpec(
        phase,
        XCRUN,
        (
            "notarytool",
            "submit",
            artifact,
            "--keychain-profile",
            credentials.notary_profile_ref,
            "--keychain",
            str(credentials.notary_keychain_ref),
            "--wait",
            "--output-format",
            "json",
        ),
        ".",
    )


def _product_notary_command_is_exact(command: CommandSpec) -> bool:
    argv = command.argv
    suffix = ".zip" if command.phase == "notary-app-submit" else ".dmg"
    return (
        command.phase in ("notary-app-submit", "notary-dmg-submit")
        and command.program == XCRUN
        and len(argv) == 10
        and argv[:2] == ("notarytool", "submit")
        and _valid_artifact(argv[2], suffix)
        and argv[3] == "--keychain-profile"
        and argv[5] == "--keychain"
        and _valid_keychain(argv[6])
        and argv[7:] == ("--wait", "--output-format", "json")
    )


def _distribution_command_is_exact(command: CommandSpec) -> bool:
    argv = command.argv
    checks = {
        "package-app-zip": command.program == _DITTO
        and argv[:4] == ("-c", "-k", "--keepParent", "--sequesterRsrc")
        and len(argv) == 6
        and _one_level(argv[4], ".app")
        and argv[5] == APP_ZIP_RELATIVE,
        "staple-app": _stapler(command, "staple", ".app"),
        "validate-app": _stapler(command, "validate", ".app"),
        "gatekeeper-app": command.program == "/usr/sbin/spctl"
        and len(argv) == 4
        and argv[:3] == ("--assess", "--type", "execute")
        and _one_level(argv[3], ".app"),
        "stage-dmg-app": command.program == _DITTO
        and len(argv) == 2
        and _one_level(argv[0], ".app")
        and argv[1] == staged_app_relative(argv[0]),
        "create-dmg": command.program == _HDIUTIL
        and argv
        == (
            "create",
            "-volname",
            "Runne",
            "-srcfolder",
            DMG_ROOT_RELATIVE,
            "-format",
            "UDZO",
            DMG_RELATIVE,
        ),
        "sign-dmg": command.program == CODESIGN
        and len(argv) == 5
        and argv[:2] == ("--force", "--sign")
        and argv[3:] == ("--timestamp", DMG_RELATIVE),
        "verify-dmg": command.program == CODESIGN
        and argv == ("--verify", "--strict", DMG_RELATIVE),
        "staple-dmg": _stapler(command, "staple", ".dmg"),
        "validate-dmg": _stapler(command, "validate", ".dmg"),
    }
    return checks.get(command.phase, False)


def _artifact_path(value: str, suffix: str) -> Path:
    path = Path(value) if isinstance(value, str) else Path()
    if not value or path.is_absolute() or ".." in path.parts or path.suffix != suffix:
        raise ValueError("invalid artifact path")
    return path


def _valid_artifact(value: str, suffix: str) -> bool:
    try:
        _artifact_path(value, suffix)
    except ValueError:
        return False
    return True


def _one_level(value: str, suffix: str) -> bool:
    return _valid_artifact(value, suffix) and len(Path(value).parts) == 1


def _valid_keychain(value: str) -> bool:
    path = Path(value) if isinstance(value, str) else Path()
    return path.is_absolute() and path.suffix in (".keychain", ".keychain-db")


def _stapler(command: CommandSpec, operation: str, suffix: str) -> bool:
    argv = command.argv
    expected = APP_ZIP_RELATIVE if suffix == ".zip" else DMG_RELATIVE
    return (
        command.program == XCRUN
        and len(argv) == 3
        and argv[:2] == ("stapler", operation)
        and ((_one_level(argv[2], ".app")) if suffix == ".app" else argv[2] == expected)
    )
