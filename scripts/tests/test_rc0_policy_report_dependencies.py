"""Dependency identity checks for report and declaration views."""

from __future__ import annotations

import inspect
import unittest

from scripts.rc0_policy.platform_policy import PolicyFailure, VerifiedDeclaration, VerifiedReport
from scripts.rc0_policy.platform_policy_report import validate_report_against_policy, verify_qualified_declaration
from scripts.tests.rc0_platform_policy_support import valid_declaration_fixture


class ReportDependencyTests(unittest.TestCase):
    def _views(self):
        fixture = valid_declaration_fixture()
        report = validate_report_against_policy(
            fixture.report, fixture.mapping.rc0_trust_policy, fixture.mapping,
            fixture.now_epoch_seconds,
        )
        declaration = verify_qualified_declaration(
            fixture.declaration, fixture.policy, fixture.mapping, fixture.resolver,
            fixture.verify_envelope, fixture.now_epoch_seconds,
        )
        return fixture, report, declaration

    def test_public_dependency_method_signatures_are_closed(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(VerifiedReport.require_dependencies).parameters),
            ("self", "mapping", "now_epoch_seconds"),
        )
        self.assertEqual(
            tuple(inspect.signature(VerifiedDeclaration.require_dependencies).parameters),
            ("self", "mapping", "report", "now_epoch_seconds"),
        )

    def test_exact_issued_dependencies_pass(self) -> None:
        fixture, report, declaration = self._views()
        VerifiedReport.require_dependencies(report, fixture.mapping, fixture.now_epoch_seconds)
        VerifiedDeclaration.require_dependencies(
            declaration, fixture.mapping, declaration.report, fixture.now_epoch_seconds,
        )

    def test_separately_minted_byte_equal_dependencies_reject(self) -> None:
        first, report, declaration = self._views()
        second, second_report, second_declaration = self._views()
        self.assertEqual(first.mapping.envelope_sha256, second.mapping.envelope_sha256)
        self.assertEqual(report.envelope_sha256, second_report.envelope_sha256)
        self.assertEqual(declaration.envelope_sha256, second_declaration.envelope_sha256)
        for mapping in (second.mapping,):
            with self.subTest(dependency="mapping"), self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
                VerifiedReport.require_dependencies(report, mapping, first.now_epoch_seconds)
            with self.subTest(dependency="declaration-mapping"), self.assertRaisesRegex(PolicyFailure, "DECLARATION_VERIFIED_INVALID"):
                VerifiedDeclaration.require_dependencies(declaration, mapping, declaration.report, first.now_epoch_seconds)
        with self.assertRaisesRegex(PolicyFailure, "DECLARATION_VERIFIED_INVALID"):
            VerifiedDeclaration.require_dependencies(
                declaration, first.mapping, second_declaration.report, first.now_epoch_seconds,
            )

    def test_wrong_type_drift_and_expiry_reject(self) -> None:
        fixture, report, declaration = self._views()
        for mapping in (None, object()):
            with self.subTest(dependency=type(mapping).__name__), self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
                report.require_dependencies(mapping, fixture.now_epoch_seconds)
        with self.assertRaisesRegex(PolicyFailure, "DECLARATION_VERIFIED_INVALID"):
            declaration.require_dependencies(fixture.mapping, None, fixture.now_epoch_seconds)
        object.__setattr__(report, "repository_id", "drifted")
        with self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
            report.require_dependencies(fixture.mapping, fixture.now_epoch_seconds)
        object.__setattr__(report, "repository_id", "gocode")
        object.__setattr__(declaration.report, "repository_id", "drifted")
        with self.assertRaisesRegex(PolicyFailure, "DECLARATION_VERIFIED_INVALID"):
            declaration.require_dependencies(fixture.mapping, declaration.report, fixture.now_epoch_seconds)
        object.__setattr__(declaration.report, "repository_id", "gocode")
        object.__setattr__(fixture.mapping.adjunct_trust, "expires_at_epoch_seconds", fixture.now_epoch_seconds - 1)
        with self.assertRaisesRegex(PolicyFailure, "REPORT_VERIFIED_INVALID"):
            report.require_dependencies(fixture.mapping, fixture.now_epoch_seconds)
        with self.assertRaisesRegex(PolicyFailure, "DECLARATION_VERIFIED_INVALID"):
            declaration.require_dependencies(fixture.mapping, declaration.report, fixture.now_epoch_seconds)


if __name__ == "__main__":
    unittest.main()
