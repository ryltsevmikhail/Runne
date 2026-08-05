"""Independent Task 12 acceptance semantics for AT20, AT24 and AT25."""

import json
import unittest

from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.model import FailureCodeV1, ReleaseFailure
from scripts.release_v2.sbom import validate_sbom
from scripts.tests.test_release_v2_dependencies import _bound_sbom, _fixture, _inventory


class SbomAcceptanceTests(unittest.TestCase):
    def test_at_20_unique_bom_refs_are_accepted(self) -> None:
        with _fixture() as root:
            inventory = _inventory(root)
        raw, product = _bound_sbom(inventory)
        document = json.loads(raw)
        validate_sbom(raw, inventory, product, structural_fixture=True)
        self.assertEqual(len({row["bom-ref"] for row in document["components"]}), len(document["components"]))

    def test_at_20_duplicate_bom_ref_blocks(self) -> None:
        with _fixture() as root:
            inventory = _inventory(root)
        raw, product = _bound_sbom(inventory)
        document = json.loads(raw)
        document["components"][1]["bom-ref"] = document["components"][0]["bom-ref"]
        self._blocks(canonical_json(document), inventory, product)

    def test_at_24_sbom_bound_to_candidate_is_accepted(self) -> None:
        with _fixture() as root:
            inventory = _inventory(root)
        raw, product = _bound_sbom(inventory)
        validate_sbom(raw, inventory, product, structural_fixture=True)
        self.assertEqual(json.loads(raw)["metadata"]["properties"][0]["value"], product.build_input_sha256)

    def test_at_24_sbom_candidate_mismatch_blocks(self) -> None:
        with _fixture() as root:
            inventory = _inventory(root)
        raw, product = _bound_sbom(inventory)
        document = json.loads(raw)
        document["metadata"]["properties"][0]["value"] = "0" * 64
        self._blocks(canonical_json(document), inventory, product)

    def test_at_25_bytewise_sorted_sbom_is_accepted(self) -> None:
        with _fixture() as root:
            inventory = _inventory(root)
        raw, product = _bound_sbom(inventory)
        validate_sbom(raw, inventory, product, structural_fixture=True)
        components = json.loads(raw)["components"]
        self.assertEqual(components, sorted(components, key=lambda row: row["bom-ref"].encode("utf-8")))

    def test_at_25_unsorted_sbom_blocks(self) -> None:
        with _fixture() as root:
            inventory = _inventory(root)
        raw, product = _bound_sbom(inventory)
        document = json.loads(raw)
        document["components"] = list(reversed(document["components"]))
        self._blocks(canonical_json(document), inventory, product)

    def _blocks(self, raw: bytes, inventory: object, product: object) -> None:
        with self.assertRaises(ReleaseFailure) as raised:
            validate_sbom(raw, inventory, product, structural_fixture=True)
        self.assertIs(raised.exception.code, FailureCodeV1.SBOM_INCOMPLETE)
