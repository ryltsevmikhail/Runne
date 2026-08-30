from pathlib import Path

from .entitlements import bind_entitlements_exact
from .models import CommandResult, FailureCode
from .observations import parse_embedded_entitlement_payload

TEAM_IDENTIFIER = "758F9Z45SR"
BUNDLE_IDENTIFIER = "com.runne.desktop"
APPLICATION_IDENTIFIER = f"{TEAM_IDENTIFIER}.{BUNDLE_IDENTIFIER}"

PRODUCT_APP_ENTITLEMENTS = {
    "com.apple.application-identifier": APPLICATION_IDENTIFIER,
    "com.apple.developer.team-identifier": TEAM_IDENTIFIER,
    "keychain-access-groups": [APPLICATION_IDENTIFIER],
}


def bind_product_entitlements(paths: tuple[Path, Path, Path]):
    return bind_entitlements_exact(
        paths,
        (PRODUCT_APP_ENTITLEMENTS, {}, {}),
    )


def parse_product_embedded_entitlements(
    role: str,
    result: CommandResult,
) -> FailureCode | None:
    payload = parse_embedded_entitlement_payload(result)
    if isinstance(payload, FailureCode):
        return payload
    expected = PRODUCT_APP_ENTITLEMENTS if role == "app" else {}
    if role not in ("app", "cli", "daemon") or payload != expected:
        return FailureCode.ENTITLEMENTS_MISMATCH
    return None
