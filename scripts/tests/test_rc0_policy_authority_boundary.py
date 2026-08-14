"""Ensure the adjunct remains a pure fixture-only verifier."""

from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2] / "scripts" / "rc0_policy"
FORBIDDEN = {"PolicyStore", "CasWriter", "KeyLoader", "activate_policy", "sign_envelope", "issue_subject"}
FLOOR_FORBIDDEN = {"floor_schema", "parse_floor", "authenticate_floor", "provision_genesis", "compare_and_swap"}


class AuthorityBoundaryTests(unittest.TestCase):
    def test_production_modules_define_no_effect_or_floor_authority(self) -> None:
        for path in ROOT.glob("*.py"):
            tree = ast.parse(path.read_text(), filename=str(path))
            names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
            with self.subTest(path=path.name):
                self.assertFalse(names & FORBIDDEN)
                self.assertFalse(names & FLOOR_FORBIDDEN)

    def test_activation_does_not_depend_on_storage_or_test_authentication(self) -> None:
        text = (ROOT / "activation.py").read_text()
        for value in ("sqlite", "redis", "boto", "Cas", "floor_bytes", "verify_fixture_floor", "_FLOOR_HEADS", "_FLOOR_SNAPSHOTS", "_fixture_floor_seal"):
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_test_support_cannot_inject_floor_tokens_or_registry_state(self) -> None:
        text = (Path(__file__).with_name("rc0_platform_activation_support.py")).read_text()
        for value in ("_TOKEN", "_FLOORS", "_FloorState", "VerifiedFloorWitness("):
            with self.subTest(value=value):
                self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
