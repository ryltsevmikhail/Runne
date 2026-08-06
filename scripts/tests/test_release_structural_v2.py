import hashlib
import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.release_v2.fixtures import generate_fixture
from scripts.tests.release_v2_acceptance import ACCEPTANCE_REGISTRY, validate_acceptance_registry


class StructuralFixtureTests(unittest.TestCase):
    def test_acceptance_registry_has_every_structural_test(self) -> None:
        validate_acceptance_registry()
        self.assertEqual(tuple(ACCEPTANCE_REGISTRY), tuple(range(1, 49)))

    def test_fixture_is_deterministic_and_inert(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary) / "first", Path(temporary) / "second"
            generate_fixture(first)
            generate_fixture(second)
            first_files = {str(path.relative_to(first)): path.read_bytes() for path in first.rglob("*") if path.is_file()}
            second_files = {str(path.relative_to(second)): path.read_bytes() for path in second.rglob("*") if path.is_file()}
        self.assertEqual(first_files, second_files)
        self.assertEqual(hashlib.sha256(first_files["archive.tar"]).hexdigest(), hashlib.sha256(second_files["archive.tar"]).hexdigest())
        self.assertIn(b"STRUCTURAL_FIXTURE", first_files["qualification-evidence.v1.json"])
        self.assertNotIn(b"PRODUCTION_RELEASE_APPROVED", first_files["claim-matrix.v1.json"])
        self.assertEqual(json.loads(first_files["fixture-result.v1.json"])["production_gate"]["disposition"], "BLOCKED")

    def test_fixture_output_must_be_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.mkdir()
            (output / "occupied").write_bytes(b"x")
            with self.assertRaises(ValueError):
                generate_fixture(output)

    def test_fixture_never_uses_network_or_process_actions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch.object(socket, "socket", side_effect=AssertionError), patch.object(subprocess, "run", side_effect=AssertionError):
            generate_fixture(Path(temporary) / "fixture")


def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None) -> unittest.TestSuite:
    suite = unittest.TestSuite()
    for module in ("test_release_v2_identity", "test_release_v2_inventory", "test_release_v2_dependencies", "test_release_v2_sbom_acceptance"):
        suite.addTests(loader.loadTestsFromName(f"scripts.tests.{module}"))
    suite.addTests(loader.loadTestsFromTestCase(StructuralFixtureTests))
    return suite
