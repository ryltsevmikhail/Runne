import unittest

from scripts.tests.release_v2_acceptance import validate_acceptance_registry


class ClaimMatrixEntrypointTests(unittest.TestCase):
    def test_acceptance_registry_is_complete(self) -> None:
        validate_acceptance_registry()


def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None) -> unittest.TestSuite:
    suite = unittest.TestSuite()
    for module in ("test_release_v2_legal", "test_release_v2_advisory_acceptance", "test_release_v2_evidence", "test_release_v2_evidence_acceptance", "test_release_v2_claim_acceptance", "test_release_v2_release_docs"):
        suite.addTests(loader.loadTestsFromName(f"scripts.tests.{module}"))
    suite.addTests(loader.loadTestsFromTestCase(ClaimMatrixEntrypointTests))
    return suite
