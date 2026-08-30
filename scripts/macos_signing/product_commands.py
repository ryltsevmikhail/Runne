from pathlib import Path

from .command_grammar import CODESIGN, XCRUN, parse_command_spec
from .models import CommandSpec, ValidatedTarget
from .product_models import (
    ExternalCommandTemplate,
    ProductionCredentialReferences,
    ProductValidatedCandidate,
)

_OPERATIONS = ("sign", "verify", "metadata", "requirement", "entitlements")
_DITTO = "/usr/bin/ditto"
_HDIUTIL = "/usr/bin/hdiutil"


def build_product_signing_commands(
    candidate: ProductValidatedCandidate,
    credentials: ProductionCredentialReferences,
) -> tuple[CommandSpec, ...]:
    if not isinstance(candidate, ProductValidatedCandidate) or not isinstance(
        credentials, ProductionCredentialReferences
    ):
        raise ValueError("invalid product signing input")
    app = ValidatedTarget(
        candidate.candidate.relative_name,
        candidate.candidate.tree_sha256,
    )
    components = (
        ("daemon", _rooted(candidate, candidate.daemon), candidate.daemon_entitlements),
        ("cli", _rooted(candidate, candidate.cli), candidate.cli_entitlements),
        ("app", app, candidate.app_entitlements),
    )
    commands = []
    for role, target, entitlement in components:
        for operation in _OPERATIONS:
            commands.append(
                _component_command(
                    role,
                    operation,
                    target,
                    entitlement,
                    credentials.signing_identity_ref,
                )
            )
    return tuple(commands)


def build_product_notary_submit_command(
    relative_zip: str,
    credentials: ProductionCredentialReferences,
) -> CommandSpec:
    path = Path(relative_zip) if isinstance(relative_zip, str) else Path()
    if (
        not isinstance(credentials, ProductionCredentialReferences)
        or not relative_zip
        or path.is_absolute()
        or len(path.parts) != 1
        or path.suffix != ".zip"
    ):
        raise ValueError("invalid notarization input")
    return _notary_command(
        "notary-app-submit",
        relative_zip,
        credentials.notary_profile_ref,
    )


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
    app = candidate.candidate.relative_name
    _artifact_name(relative_zip, ".zip")
    _artifact_name(relative_dmg, ".dmg")
    return (
        CommandSpec(
            "package-app-zip",
            _DITTO,
            ("-c", "-k", "--keepParent", "--sequesterRsrc", app, relative_zip),
            ".",
        ),
        _notary_command(
            "notary-app-submit",
            relative_zip,
            credentials.notary_profile_ref,
        ),
        CommandSpec("staple-app", XCRUN, ("stapler", "staple", app), "."),
        CommandSpec("validate-app", XCRUN, ("stapler", "validate", app), "."),
        CommandSpec(
            "gatekeeper-app",
            "/usr/sbin/spctl",
            ("--assess", "--type", "execute", app),
            ".",
        ),
        CommandSpec(
            "create-dmg",
            _HDIUTIL,
            (
                "create",
                "-volname",
                "Runne",
                "-srcfolder",
                app,
                "-format",
                "UDZO",
                relative_dmg,
            ),
            ".",
        ),
        CommandSpec(
            "sign-dmg",
            CODESIGN,
            ("--force", "--sign", credentials.signing_identity_ref, "--timestamp", relative_dmg),
            ".",
        ),
        CommandSpec("verify-dmg", CODESIGN, ("--verify", "--strict", relative_dmg), "."),
        _notary_command(
            "notary-dmg-submit",
            relative_dmg,
            credentials.notary_profile_ref,
        ),
        CommandSpec("staple-dmg", XCRUN, ("stapler", "staple", relative_dmg), "."),
        CommandSpec("validate-dmg", XCRUN, ("stapler", "validate", relative_dmg), "."),
    )


def redact_external_command(command: CommandSpec) -> ExternalCommandTemplate:
    if _product_notary_command_is_exact(command):
        argv = list(command.argv)
        argv[4] = "<NOTARY_PROFILE_REF>"
        return ExternalCommandTemplate(command.phase, command.program, tuple(argv))
    if _distribution_command_is_exact(command):
        argv = list(command.argv)
        if command.phase == "sign-dmg":
            argv[2] = "<SIGNING_IDENTITY_REF>"
        return ExternalCommandTemplate(command.phase, command.program, tuple(argv))
    parsed = parse_command_spec(command)
    if parsed is None:
        raise ValueError("invalid product command")
    argv = list(command.argv)
    if command.phase.startswith("sign-"):
        argv[2] = "<SIGNING_IDENTITY_REF>"
    return ExternalCommandTemplate(command.phase, command.program, tuple(argv))


def _product_notary_command_is_exact(command: CommandSpec) -> bool:
    argv = command.argv
    return (
        command.phase in ("notary-app-submit", "notary-dmg-submit")
        and command.program == XCRUN
        and len(argv) == 8
        and argv[:2] == ("notarytool", "submit")
        and Path(argv[2]).suffix
        == (".zip" if command.phase == "notary-app-submit" else ".dmg")
        and len(Path(argv[2]).parts) == 1
        and argv[3] == "--keychain-profile"
        and argv[5:] == ("--wait", "--output-format", "json")
    )


def _distribution_command_is_exact(command: CommandSpec) -> bool:
    argv = command.argv
    checks = {
        "package-app-zip": command.program == _DITTO
        and len(argv) == 6
        and argv[:4] == ("-c", "-k", "--keepParent", "--sequesterRsrc")
        and _suffix(argv[4], ".app")
        and _suffix(argv[5], ".zip"),
        "staple-app": _stapler(command, "staple", ".app"),
        "validate-app": _stapler(command, "validate", ".app"),
        "gatekeeper-app": command.program == "/usr/sbin/spctl"
        and argv[:3] == ("--assess", "--type", "execute")
        and len(argv) == 4
        and _suffix(argv[3], ".app"),
        "create-dmg": command.program == _HDIUTIL
        and len(argv) == 8
        and argv[:4] == ("create", "-volname", "Runne", "-srcfolder")
        and _suffix(argv[4], ".app")
        and argv[5:7] == ("-format", "UDZO")
        and _suffix(argv[7], ".dmg"),
        "sign-dmg": command.program == CODESIGN
        and len(argv) == 5
        and argv[:2] == ("--force", "--sign")
        and argv[3] == "--timestamp"
        and _suffix(argv[4], ".dmg"),
        "verify-dmg": command.program == CODESIGN
        and len(argv) == 3
        and argv[:2] == ("--verify", "--strict")
        and _suffix(argv[2], ".dmg"),
        "staple-dmg": _stapler(command, "staple", ".dmg"),
        "validate-dmg": _stapler(command, "validate", ".dmg"),
    }
    return checks.get(command.phase, False)


def _notary_command(phase: str, artifact: str, profile: str) -> CommandSpec:
    return CommandSpec(
        phase,
        XCRUN,
        (
            "notarytool",
            "submit",
            artifact,
            "--keychain-profile",
            profile,
            "--wait",
            "--output-format",
            "json",
        ),
        ".",
    )


def _artifact_name(value: str, suffix: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid artifact name")
    path = Path(value)
    if path.is_absolute() or len(path.parts) != 1 or path.suffix != suffix:
        raise ValueError("invalid artifact name")
    return value


def _suffix(value: str, suffix: str) -> bool:
    try:
        _artifact_name(value, suffix)
    except ValueError:
        return False
    return True


def _stapler(command: CommandSpec, operation: str, suffix: str) -> bool:
    return (
        command.program == XCRUN
        and len(command.argv) == 3
        and command.argv[:2] == ("stapler", operation)
        and _suffix(command.argv[2], suffix)
    )


def _component_command(
    role: str,
    operation: str,
    target: ValidatedTarget,
    entitlement,
    identity_reference: str,
) -> CommandSpec:
    phase = f"{operation}-{role}"
    if operation == "sign":
        argv = (
            "--force",
            "--sign",
            identity_reference,
            "--timestamp",
            "--options",
            "runtime",
            "--entitlements",
            f"{role}.plist",
            target.relative_path,
        )
        return CommandSpec(phase, CODESIGN, argv, ".", entitlement)
    arguments = {
        "verify": ("--verify", "--strict", target.relative_path),
        "metadata": ("-dvv", target.relative_path),
        "requirement": ("-d", "-r-", target.relative_path),
        "entitlements": ("-d", "--entitlements", ":-", target.relative_path),
    }
    try:
        argv = arguments[operation]
    except KeyError:
        raise ValueError("unknown product operation") from None
    return CommandSpec(phase, CODESIGN, argv, ".")


def _rooted(
    candidate: ProductValidatedCandidate,
    target: ValidatedTarget,
) -> ValidatedTarget:
    return ValidatedTarget(
        f"{candidate.candidate.relative_name}/{target.relative_path}",
        target.sha256,
    )
