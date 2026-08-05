"""Regression contract for canonical Task 12 human fixture bytes."""

import hashlib
import importlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.release_v2.fixtures import generate_fixture
from scripts.release_v2 import human_fixture_validation as human_validation
from scripts.release_v2.human_fixture_validation import validate_human_fixture
from scripts.release_v2.model import FailureCodeV1, ReleaseFailure


_HUMAN_SHA256 = {
    "human/binding.v1.json": "1cddc968005d42ad26e6d7a25664d015970c5838e19efa29afc7837ad17e5bf9",
    "human/changelog.md": "89ef68f54644b8969f67e2ea750205356d9167e311d30f2a8c9a182222df74d1",
    "human/release-notes.md": "c8983e72540cbbddc496a46ca24cd150ffc7406d555f46f17a054b724d2f047c",
    "human/rollback.md": "a59e4184ba2ced1a602e59fab5474a712ff4588402c8e753320a3f39185f727a",
    "human/pr-description.md": "32a3824bd219d9ea8382fc6c2200cb4a71e09fa8f90101c2b280df2cd790ef2d",
    "human/merge-checklist.md": "2791122edb862faa75eb0acd9ad08daace5696fe343a68a36ea03ccbc1e23b0c",
}
_CHECKSUM_SIDECAR = "c8fbbd7d6311457ef2fda310ede748e1e753ee2de630290628a25e2d6504328b  checksums.sha256\n"
_DOCUMENTS = tuple(name for name in _HUMAN_SHA256 if name != "human/binding.v1.json")


class HumanFixtureContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "fixture"
        generate_fixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_leaf_contract_has_hardcoded_canonical_output_digests(self) -> None:
        binding = self._binding()
        try:
            contract = importlib.import_module("scripts.release_v2.human_fixture_contract")
        except ModuleNotFoundError:
            self.fail("human fixture contract leaf is required")
        values = contract.canonical_human_artifacts(
            binding["candidate_sha256"], binding["version"], binding["source_sha256"]
        )
        self.assertEqual(
            {name: hashlib.sha256(raw).hexdigest() for name, raw in values.items()},
            _HUMAN_SHA256,
        )

    def test_generator_writes_exact_human_sidecars_and_checksum_sidecar(self) -> None:
        for name, digest in _HUMAN_SHA256.items():
            with self.subTest(name=name):
                self.assertEqual(
                    (self.root / f"{name}.sha256").read_bytes(),
                    f"{digest}  {name}\n".encode(),
                )
        self.assertEqual(
            (self.root / "checksums.sha256.sha256").read_text(encoding="utf-8"),
            _CHECKSUM_SIDECAR,
        )

    def test_five_document_extra_prose_bypasses_block(self) -> None:
        for index, name in enumerate(_DOCUMENTS):
            with self.subTest(name=name):
                self._fresh(index)
                self._replace(name, (self.root / name).read_bytes() + b"\nInert extra prose.\n")
                self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def test_binding_json_whitespace_bypass_blocks(self) -> None:
        name = "human/binding.v1.json"
        self._replace(name, b"\n" + (self.root / name).read_bytes())
        self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def test_each_human_byte_change_with_recomputed_sidecar_blocks(self) -> None:
        for index, name in enumerate(_HUMAN_SHA256):
            with self.subTest(name=name):
                self._fresh(index)
                self._replace(name, (self.root / name).read_bytes() + b" ")
                self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def test_tampering_blocks_when_scanner_reports_no_command(self) -> None:
        name = "human/changelog.md"
        self._replace(name, (self.root / name).read_bytes() + b"\nInert extra prose.\n")
        with patch.object(human_validation, "contains_production_command", return_value=False):
            self._blocks(FailureCodeV1.MANIFEST_INVALID)

    def _binding(self) -> dict[str, str]:
        import json

        return json.loads((self.root / "human/binding.v1.json").read_text(encoding="utf-8"))

    def _fresh(self, index: int) -> None:
        self.root = Path(self.temporary.name) / f"fixture-{index}"
        generate_fixture(self.root)

    def _replace(self, name: str, raw: bytes) -> None:
        target = self.root / name
        target.write_bytes(raw)
        (self.root / f"{name}.sha256").write_text(
            f"{hashlib.sha256(raw).hexdigest()}  {name}\n", encoding="utf-8"
        )

    def _blocks(self, code: FailureCodeV1) -> None:
        with self.assertRaises(ReleaseFailure) as raised:
            validate_human_fixture(self.root)
        self.assertIs(raised.exception.code, code)
