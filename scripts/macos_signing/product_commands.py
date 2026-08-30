from pathlib import Path

from .command_grammar import CODESIGN, parse_command_spec
from .models import CommandSpec, ValidatedTarget
from .product_distribution_commands import (
    build_product_distribution_commands,
    build_product_notary_submit_command,
    canonical_distribution_templates,
    redact_distribution_command,
)
from .product_models import (
    ExternalCommandTemplate,
    ProductionCredentialReferences,
    ProductValidatedCandidate,
)

_OPERATIONS = ("sign", "verify", "metadata", "requirement", "entitlements")
_SECURITY = "/usr/bin/security"


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
    commands = [
        CommandSpec(
            "inspect-provisioning-profile",
            _SECURITY,
            (
                "cms",
                "-D",
                "-i",
                f"{candidate.candidate.relative_name}/Contents/embedded.provisionprofile",
            ),
            ".",
        )
    ]
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


def redact_external_command(command: CommandSpec) -> ExternalCommandTemplate:
    if _profile_inspection_is_exact(command):
        return ExternalCommandTemplate(command.phase, command.program, command.argv)
    distribution = redact_distribution_command(command)
    if distribution is not None:
        return distribution
    parsed = parse_command_spec(command)
    if parsed is None:
        raise ValueError("invalid product command")
    argv = list(command.argv)
    if command.phase.startswith("sign-"):
        argv[2] = "<SIGNING_IDENTITY_REF>"
    return ExternalCommandTemplate(command.phase, command.program, tuple(argv))


def canonical_product_templates(app_name: str) -> tuple[ExternalCommandTemplate, ...]:
    targets = {
        "daemon": f"{app_name}/Contents/MacOS/runned",
        "cli": f"{app_name}/Contents/MacOS/runne",
        "app": app_name,
    }
    templates = [
        ExternalCommandTemplate(
            "inspect-provisioning-profile",
            _SECURITY,
            ("cms", "-D", "-i", f"{app_name}/Contents/embedded.provisionprofile"),
        )
    ]
    for role in ("daemon", "cli", "app"):
        target = targets[role]
        arguments = {
            "sign": (
                "--force",
                "--sign",
                "<SIGNING_IDENTITY_REF>",
                "--timestamp",
                "--options",
                "runtime",
                "--entitlements",
                f"{role}.plist",
                target,
            ),
            "verify": ("--verify", "--strict", target),
            "metadata": ("-dvvv", target),
            "requirement": ("-d", "-r-", target),
            "entitlements": ("-d", "--entitlements", ":-", target),
        }
        for operation in _OPERATIONS:
            templates.append(
                ExternalCommandTemplate(
                    f"{operation}-{role}",
                    CODESIGN,
                    arguments[operation],
                )
            )
    return tuple(templates) + canonical_distribution_templates(app_name)


def _profile_inspection_is_exact(command: CommandSpec) -> bool:
    return (
        command.phase == "inspect-provisioning-profile"
        and command.program == _SECURITY
        and len(command.argv) == 4
        and command.argv[:3] == ("cms", "-D", "-i")
        and command.argv[3].endswith(".app/Contents/embedded.provisionprofile")
        and not command.argv[3].startswith("/")
        and ".." not in Path(command.argv[3]).parts
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
        "metadata": ("-dvvv", target.relative_path),
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
