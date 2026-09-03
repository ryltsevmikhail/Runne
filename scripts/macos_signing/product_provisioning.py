import plistlib
from datetime import UTC, datetime

from .models import CommandResult, FailureCode
from .product_entitlements import (
    APPLICATION_IDENTIFIER,
    BUNDLE_IDENTIFIER,
    CREDENTIAL_SERVICE_APPLICATION_IDENTIFIER,
    TEAM_IDENTIFIER,
)

MAX_PROFILE_OUTPUT_BYTES = 128 * 1024


def profile_result_failure(role: str, result: CommandResult) -> FailureCode | None:
    if not isinstance(result, CommandResult):
        return FailureCode.UNKNOWN_STATUS
    if result.exit_code != 0:
        return _reported_failure(result)
    if (
        not isinstance(result.stdout, str)
        or len(result.stdout.encode()) > MAX_PROFILE_OUTPUT_BYTES
    ):
        return FailureCode.UNKNOWN_STATUS
    try:
        profile = plistlib.loads(result.stdout.encode())
    except (plistlib.InvalidFileException, ValueError):
        return FailureCode.UNKNOWN_STATUS
    expected = {
        "app": APPLICATION_IDENTIFIER,
        "credential-service": CREDENTIAL_SERVICE_APPLICATION_IDENTIFIER,
    }.get(role)
    if expected is None or not _profile_authorizes_product(profile, expected):
        return FailureCode.ENTITLEMENTS_MISMATCH
    return None


def _profile_authorizes_product(profile: object, expected_identifier: str) -> bool:
    if type(profile) is not dict:
        return False
    entitlements = profile.get("Entitlements")
    expires = profile.get("ExpirationDate")
    if (
        type(entitlements) is not dict
        or profile.get("TeamIdentifier") != [TEAM_IDENTIFIER]
        or profile.get("ProvisionsAllDevices") is not True
        or not isinstance(expires, datetime)
        or expires <= datetime.now(UTC).replace(tzinfo=None)
    ):
        return False
    application_identifier = entitlements.get("com.apple.application-identifier")
    groups = entitlements.get("keychain-access-groups")
    prefix = APPLICATION_IDENTIFIER.removesuffix(BUNDLE_IDENTIFIER)
    return (
        application_identifier == expected_identifier
        and entitlements.get("com.apple.developer.team-identifier")
        == TEAM_IDENTIFIER
        and type(groups) is list
        and all(isinstance(group, str) for group in groups)
        and any(group in (expected_identifier, f"{prefix}*") for group in groups)
        and entitlements.get("get-task-allow") is not True
        and entitlements.get("com.apple.security.get-task-allow") is not True
    )


def _reported_failure(result: CommandResult) -> FailureCode:
    for output in (result.stdout, result.stderr):
        try:
            failure = FailureCode(output.strip())
        except (AttributeError, ValueError):
            continue
        if failure in (FailureCode.TOOL_UNAVAILABLE, FailureCode.ENTITLEMENTS_MISMATCH):
            return failure
    return FailureCode.ENTITLEMENTS_MISMATCH
