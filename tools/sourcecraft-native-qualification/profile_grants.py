"""Fail-closed compatibility checks between macOS profile grants and signed entitlements."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from codec import Rejected


def validate(value: object, application_identifier: str, signed_entitlements: object,
             team: str, now: datetime | None = None) -> None:
    if not isinstance(value, dict) or not isinstance(signed_entitlements, dict):
        raise Rejected("provisioning measurement differs")
    if not _metadata(value, team, now):
        raise Rejected("provisioning measurement differs")
    grant = value.get("Entitlements")
    if not isinstance(grant, dict) or not _allows(grant, application_identifier, signed_entitlements, team):
        raise Rejected("provisioning measurement differs")


def _metadata(value: dict[str, object], team: str, now: datetime | None) -> bool:
    if value.get("ApplicationIdentifierPrefix") != [team] or value.get("TeamIdentifier") != [team] or value.get("Platform") != ["OSX"] or value.get("ProvisionsAllDevices") is not True:
        return False
    identifier = value.get("UUID")
    ttl = value.get("TimeToLive")
    dates = value.get("CreationDate"), value.get("ExpirationDate")
    if not isinstance(identifier, str) or not _uuid(identifier) or type(ttl) is not int or not 0 < ttl <= 999_999_999 or not all(isinstance(date, datetime) for date in dates):
        return False
    created, expires = (_utc(date) for date in dates)
    observed = _utc(now or datetime.now(timezone.utc))
    return created < expires and created <= observed < expires and expires - created <= timedelta(days=ttl)


def _allows(grant: dict[str, object], application_identifier: str,
            signed: dict[str, object], team: str) -> bool:
    permitted = {"com.apple.application-identifier", "com.apple.developer.team-identifier", "keychain-access-groups", "com.apple.security.get-task-allow"}
    if set(grant) - permitted or grant.get("com.apple.application-identifier") != application_identifier or grant.get("com.apple.developer.team-identifier") != team:
        return False
    if "com.apple.security.get-task-allow" in grant and (
        type(grant["com.apple.security.get-task-allow"]) is not bool
        or grant["com.apple.security.get-task-allow"] is not False
    ):
        return False
    groups = grant.get("keychain-access-groups")
    signed_groups = signed.get("keychain-access-groups")
    exact_groups = [application_identifier]
    if groups not in ([f"{team}.*"], exact_groups) or signed_groups != exact_groups:
        return False
    return signed.get("com.apple.application-identifier") == application_identifier and signed.get("com.apple.developer.team-identifier") == team


def _uuid(value: str) -> bool:
    try:
        return str(UUID(value)) == value.lower()
    except ValueError:
        return False


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
