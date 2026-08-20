from pathlib import Path
from typing import Literal

from .command_grammar import CODESIGN, SPCTL, XCRUN
from .models import CommandSpec, EntitlementBinding, SigningProfile, ValidatedCandidate, ValidatedTarget
from .state import NotarizationArtifactBinding


def build_sign_command(
    target: ValidatedTarget,
    entitlements: Path,
    profile: SigningProfile,
    identity_reference: str,
    entitlement_binding: EntitlementBinding | None = None,
) -> CommandSpec:
    _profile(profile)
    argv = ["--force", "--sign", _identity(identity_reference, profile), "--entitlements", _plist(target, entitlements)]
    if profile is SigningProfile.PRODUCTION_DEVELOPER_ID:
        argv.extend(("--options", "runtime"))
    argv.append(_target(target))
    return CommandSpec(_phase("sign", target), CODESIGN, tuple(argv), ".", entitlement_binding)


def build_verify_command(target: ValidatedTarget, profile: SigningProfile) -> CommandSpec:
    _profile(profile)
    return CommandSpec(_phase("verify", target), CODESIGN, ("--verify", "--strict", _target(target)), ".")


def build_metadata_command(target: ValidatedTarget) -> CommandSpec:
    return CommandSpec(_phase("metadata", target), CODESIGN, ("-dvv", _target(target)), ".")


def build_requirement_command(target: ValidatedTarget) -> CommandSpec:
    return CommandSpec(_phase("requirement", target), CODESIGN, ("-d", "-r-", _target(target)), ".")


def build_entitlement_command(target: ValidatedTarget) -> CommandSpec:
    return CommandSpec(
        _phase("entitlements", target),
        CODESIGN,
        ("-d", "--entitlements", ":-", _target(target)),
        ".",
    )


def build_notary_submit_command(artifact: NotarizationArtifactBinding, keychain_profile_ref: str) -> CommandSpec:
    if not isinstance(artifact, NotarizationArtifactBinding):
        raise ValueError("invalid notarization artifact")
    return CommandSpec(
        "notary-submit",
        XCRUN,
        ("notarytool", "submit", _relative(artifact.relative_path), "--keychain-profile", _reference(keychain_profile_ref), "--wait", "--output-format", "json"),
        ".",
        notarization_artifact=artifact,
    )


def build_staple_command(
    candidate: ValidatedTarget,
    operation: Literal["staple", "validate"],
) -> CommandSpec:
    if operation not in ("staple", "validate"):
        raise ValueError("invalid stapler operation")
    return CommandSpec("staple-" + operation, XCRUN, ("stapler", operation, _candidate(candidate)), ".")


def build_gatekeeper_command(candidate: ValidatedTarget) -> CommandSpec:
    return CommandSpec(
        "gatekeeper",
        SPCTL,
        ("--assess", "--type", "execute", _candidate(candidate)),
        ".",
    )


def _target(target: ValidatedTarget) -> str:
    value = _artifact(target)
    parts = Path(value).parts
    if len(parts) == 4 and parts[1:] == ("Contents", "MacOS", "runned") and Path(parts[0]).suffix == ".app":
        return value
    if len(parts) == 1 and Path(value).suffix == ".app":
        return value
    raise ValueError("invalid target")


def _artifact(target: ValidatedTarget) -> str:
    if not isinstance(target, ValidatedTarget):
        raise ValueError("invalid target")
    return _relative(target.relative_path)


def _candidate(target: ValidatedTarget) -> str:
    value = _artifact(target)
    if Path(value).suffix != ".app":
        raise ValueError("invalid app candidate")
    return value


def _plist(target: ValidatedTarget, entitlements: Path) -> str:
    expected = _phase("", target).removeprefix("-") + ".plist"
    if not isinstance(entitlements, Path) or str(entitlements) != expected:
        raise ValueError("invalid entitlements token")
    return expected


def _profile(profile: SigningProfile) -> None:
    if not isinstance(profile, SigningProfile):
        raise ValueError("invalid signing profile")


def _reference(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("-"):
        raise ValueError("invalid external reference")
    return value


def _identity(value: str, profile: SigningProfile) -> str:
    if value == "-" and profile is SigningProfile.DEVELOPMENT_AD_HOC:
        return value
    return _reference(value)


def _relative(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("path must be candidate-relative")
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError("path must be candidate-relative")
    return value


def _phase(prefix: str, target: ValidatedTarget) -> str:
    suffix = "daemon" if _target(target).endswith("/runned") else "app"
    return prefix + "-" + suffix if prefix else suffix


def rooted_target(candidate: ValidatedCandidate, target: ValidatedTarget) -> ValidatedTarget:
    return ValidatedTarget(f"{candidate.candidate.relative_name}/{target.relative_path}", target.sha256)


def bundle_target(candidate: ValidatedCandidate) -> ValidatedTarget:
    return ValidatedTarget(candidate.candidate.relative_name, candidate.candidate.tree_sha256)
