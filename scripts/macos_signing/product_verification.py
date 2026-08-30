from .models import CommandResult, CommandSpec, FailureCode
from .observations import (
    parse_designated_requirement,
    parse_signature_metadata,
)
from .parsers import (
    parse_codesign_result,
    parse_notary_result,
    parse_spctl_result,
    parse_stapler_result,
)
from .product_entitlements import parse_product_embedded_entitlements
from .product_provisioning import profile_result_failure

_EXPECTED_IDENTIFIERS = {
    "daemon": "runned",
    "cli": "runne",
    "app": "com.runne.desktop",
}
_TEAM_ID = "758F9Z45SR"


def verify_product_command_result(
    command: CommandSpec,
    result: CommandResult,
) -> FailureCode | None:
    phase = command.phase
    if phase == "inspect-provisioning-profile":
        return profile_result_failure(result)
    if phase.startswith(("sign-", "verify-")):
        return parse_codesign_result(result)
    if phase.startswith("metadata-"):
        return _metadata_failure(phase.removeprefix("metadata-"), result)
    if phase.startswith("requirement-"):
        value = parse_designated_requirement(result)
        return value if isinstance(value, FailureCode) else None
    if phase.startswith("entitlements-"):
        return parse_product_embedded_entitlements(
            phase.removeprefix("entitlements-"),
            result,
        )
    if phase.startswith("notary-"):
        return parse_notary_result(result)
    if phase.startswith(("staple-", "validate-")):
        return parse_stapler_result(result)
    if phase == "gatekeeper-app":
        return parse_spctl_result(result)
    if phase in ("package-app-zip", "stage-dmg-app", "create-dmg"):
        return _generic_failure(result)
    return FailureCode.UNKNOWN_STATUS


def _metadata_failure(role: str, result: CommandResult) -> FailureCode | None:
    observed = parse_signature_metadata(result)
    if isinstance(observed, FailureCode):
        return observed
    if (
        observed.bundle_id != _EXPECTED_IDENTIFIERS.get(role)
        or observed.team_identifier != _TEAM_ID
        or observed.authority_class != "Developer ID Application"
    ):
        return FailureCode.ARTIFACT_IDENTITY_MISMATCH
    return None


def _generic_failure(result: CommandResult) -> FailureCode | None:
    if not isinstance(result, CommandResult):
        return FailureCode.UNKNOWN_STATUS
    if result.exit_code == 0:
        return None
    for value in (result.stdout, result.stderr):
        try:
            return FailureCode(value.strip())
        except (AttributeError, ValueError):
            continue
    return FailureCode.UNKNOWN_STATUS
