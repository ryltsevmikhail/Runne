from pathlib import Path

from .command_grammar import CODESIGN, XCRUN, parse_command_spec
from .models import CommandSpec, ValidatedTarget
from .product_models import (
    ExternalCommandTemplate,
    ProductionCredentialReferences,
    ProductValidatedCandidate,
)

_OPERATIONS = ("sign", "verify", "metadata", "requirement", "entitlements")


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
    return CommandSpec(
        "notary-app-submit",
        XCRUN,
        (
            "notarytool",
            "submit",
            relative_zip,
            "--keychain-profile",
            credentials.notary_profile_ref,
            "--wait",
            "--output-format",
            "json",
        ),
        ".",
    )


def redact_external_command(command: CommandSpec) -> ExternalCommandTemplate:
    if _product_notary_command_is_exact(command):
        argv = list(command.argv)
        argv[4] = "<NOTARY_PROFILE_REF>"
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
        command.phase == "notary-app-submit"
        and command.program == XCRUN
        and len(argv) == 8
        and argv[:2] == ("notarytool", "submit")
        and Path(argv[2]).suffix == ".zip"
        and len(Path(argv[2]).parts) == 1
        and argv[3] == "--keychain-profile"
        and argv[5:] == ("--wait", "--output-format", "json")
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
