from __future__ import annotations

import copy
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE))
from codec import Rejected
from contract import DEPLOYMENT, TEAM
from profile_grants import validate


class ProfileGrantTests(unittest.TestCase):
    def _profile(self, groups: list[str] | None = None) -> dict[str, object]:
        application = f"{TEAM}.com.runne.credential-service"
        return {
            "Name":"untrusted arbitrary label", "UUID":"00000000-0000-0000-0000-000000000001",
            "TimeToLive":365, "CreationDate":datetime(2026, 1, 1, tzinfo=timezone.utc),
            "ExpirationDate":datetime(2027, 1, 1, tzinfo=timezone.utc),
            "ApplicationIdentifierPrefix":[TEAM], "Platform":["OSX"], "ProvisionsAllDevices":True,
            "TeamIdentifier":[TEAM], "Entitlements":{
                "com.apple.application-identifier":application,
                "com.apple.developer.team-identifier":TEAM,
                "keychain-access-groups":groups or [application],
            },
        }

    def test_exact_and_team_wildcard_grants_cover_only_exact_signed_group(self) -> None:
        application = f"{TEAM}.com.runne.credential-service"
        signed = DEPLOYMENT["entitlements"]["service"]
        validate(self._profile(), application, signed, TEAM, datetime(2026, 6, 1, tzinfo=timezone.utc))
        validate(self._profile([f"{TEAM}.*"]), application, signed, TEAM, datetime(2026, 6, 1, tzinfo=timezone.utc))

    def test_invalid_grants_and_metadata_fail_closed(self) -> None:
        application = f"{TEAM}.com.runne.credential-service"
        signed = DEPLOYMENT["entitlements"]["service"]
        cases: list[tuple[str, object, object]] = []
        profile = self._profile(); profile["Entitlements"]["com.apple.security.get-task-allow"] = True; cases.append(("debug", profile, signed))
        profile = self._profile(); profile["Entitlements"]["com.apple.security.get-task-allow"] = 0; cases.append(("numeric-debug", profile, signed))
        profile = self._profile(); profile["Entitlements"]["com.apple.application-identifier"] = f"{TEAM}.*"; cases.append(("wildcard-app", profile, signed))
        profile = self._profile([f"{TEAM}.com.runne.*"]); cases.append(("generic-group", profile, signed))
        profile = self._profile(); profile["UUID"] = "not-a-uuid"; cases.append(("uuid", profile, signed))
        profile = self._profile(); profile["TimeToLive"] = 2**63 - 1; cases.append(("overflow-ttl", profile, signed))
        extra = copy.deepcopy(signed); extra["keychain-access-groups"].append(f"{TEAM}.other")
        cases.append(("extra-signed-group", self._profile([f"{TEAM}.*"]), extra))
        for name, profile, entitlements in cases:
            with self.subTest(name=name):
                with self.assertRaises(Rejected):
                    validate(profile, application, entitlements, TEAM, datetime(2026, 6, 1, tzinfo=timezone.utc))
