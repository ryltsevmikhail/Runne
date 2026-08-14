"""Task 6 successor-trust schema vectors."""

from copy import deepcopy
import unittest

from scripts.tests.test_project_owner_authority_schemas import _errors, _schema, load_fixture


class ProjectOwnerAuthorityRotationSchemaTests(unittest.TestCase):
    def test_trust_config_accepts_only_epoch_conditioned_predecessors(self) -> None:
        schema = _schema("trust-config")
        self.assertFalse(_errors(schema, load_fixture("trust-config-successor")))
        genesis = deepcopy(load_fixture("trust-config"))
        genesis["predecessor"] = "a" * 64
        self.assertTrue(_errors(schema, genesis))
        successor = deepcopy(load_fixture("trust-config-successor"))
        successor["predecessor"] = None
        self.assertTrue(_errors(schema, successor))
