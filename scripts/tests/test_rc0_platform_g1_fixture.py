"""Regression tests for the superseded legacy G1 receipt boundary."""

from __future__ import annotations

import ast
from pathlib import Path
import unittest

from scripts.rc0_policy import owner_authority_receipt as legacy_g1
from scripts.rc0_policy import activation, platform_matrix, platform_policy_mapping, qualified_subject


SUPERSEDED_G1_UNSUPPORTED = "SUPERSEDED_G1_UNSUPPORTED"
_VALID_LOOKING_RECEIPT = (
    b'{"payload_schema_id":"gocode.rc0.post-rc0-owner-authority-receipt/1",'
    b'"signature":"00"}'
)
_VERIFY_ENTRYPOINTS = (
    "verify_g1_authority_receipt",
    "verify_owner_authority_receipt",
)


class G1FixtureShimTests(unittest.TestCase):
    def assert_superseded(self, call: object) -> None:
        with self.assertRaises(legacy_g1.G1Failure) as raised:
            call()
        self.assertEqual(raised.exception.code, SUPERSEDED_G1_UNSUPPORTED)
        self.assertEqual(str(raised.exception), SUPERSEDED_G1_UNSUPPORTED)

    def test_all_legacy_entrypoints_reject_empty_arguments(self) -> None:
        for name in (*_VERIFY_ENTRYPOINTS, "require_production_g1"):
            with self.subTest(name=name):
                self.assert_superseded(getattr(legacy_g1, name))

    def test_verifiers_reject_bytes_and_historical_domains_before_parsing(self) -> None:
        for name in _VERIFY_ENTRYPOINTS:
            verifier = getattr(legacy_g1, name)
            for raw in (b"", _VALID_LOOKING_RECEIPT):
                for domain in ("FIXTURE_ONLY", "PRODUCTION"):
                    with self.subTest(name=name, raw=raw, domain=domain):
                        self.assert_superseded(
                            lambda: verifier(raw, required_verification_domain=domain)
                        )

    def test_verifiers_never_invoke_hostile_callback(self) -> None:
        for name in _VERIFY_ENTRYPOINTS:
            called = False

            def hostile_callback(*args: object, **kwargs: object) -> object:
                nonlocal called
                called = True
                raise AssertionError("legacy verifier must not be invoked")

            verifier = getattr(legacy_g1, name)
            with self.subTest(name=name):
                self.assert_superseded(
                    lambda: verifier(
                        _VALID_LOOKING_RECEIPT,
                        object(),
                        hostile_callback,
                        object(),
                        object(),
                        required_verification_domain="FIXTURE_ONLY",
                    )
                )
                self.assertFalse(called)

    def test_require_production_g1_never_invokes_hostile_object(self) -> None:
        called = False

        class HostileReceipt:
            def __getattribute__(self, name: str) -> object:
                nonlocal called
                called = True
                raise AssertionError("legacy receipt must not be inspected")

        self.assert_superseded(lambda: legacy_g1.require_production_g1(HostileReceipt()))
        self.assertFalse(called)

    def test_shim_has_no_verifier_dependencies_or_verified_view(self) -> None:
        source = Path(legacy_g1.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_modules = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_modules.update(
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        forbidden = ("cryptography", "external_envelope", "registry", "signature")
        self.assertFalse(
            any(term in module for module in imported_modules for term in forbidden)
        )
        self.assertNotIn("VerifiedOwnerAuthorityReceipt", source)
        self.assertFalse(
            any(
                isinstance(node, ast.ClassDef)
                and node.name == "VerifiedOwnerAuthorityReceipt"
                for node in ast.walk(tree)
            )
        )

    def test_legacy_g1_lifecycle_entrypoints_reject_before_argument_access(self) -> None:
        class Hostile:
            def __getattribute__(self, name: str) -> object:
                raise AssertionError("G1 input must not be inspected")

        for entrypoint in (
            platform_policy_mapping.verify_mapping_policy,
            activation.verify_activation,
            qualified_subject.collect_authority_roles,
            qualified_subject.verify_qualified_subject,
            platform_matrix.verify_platform_matrix,
        ):
            with self.subTest(entrypoint=entrypoint.__name__):
                with self.assertRaisesRegex(ValueError, SUPERSEDED_G1_UNSUPPORTED):
                    entrypoint(Hostile())


if __name__ == "__main__":
    unittest.main()
