"""Validate the frozen syntactic Workgroup v1 contract fixtures."""

from __future__ import annotations

import json
import hashlib
from copy import deepcopy
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).parents[2]
SCHEMAS = ROOT / "docs" / "schemas"
GOLDEN = ROOT / "docs" / "golden"


class WorkgroupSchemaTests(unittest.TestCase):
    def test_schemas_are_valid_draft_2020_12(self) -> None:
        for name in ("workgroup-message-v1.schema.json", "workgroup-board-v1.schema.json"):
            with self.subTest(name=name):
                Draft202012Validator.check_schema(self._json(SCHEMAS / name))

    def test_message_golden_vectors(self) -> None:
        self._assert_vectors("workgroup-message-v1.schema.json", "workgroup-message-v1")

    def test_board_golden_vectors(self) -> None:
        self._assert_vectors("workgroup-board-v1.schema.json", "workgroup-board-v1")

    def test_board_command_payloads_are_discriminated(self) -> None:
        command = self._json(GOLDEN / "workgroup-board-v1" / "valid-command.json")
        validator = Draft202012Validator(
            self._json(SCHEMAS / "workgroup-board-v1.schema.json"), format_checker=FormatChecker()
        )
        cases = {
            "update_task": {"task_id": "018f2e3a-7000-7000-8000-000000000202", "title": "Новый заголовок"},
            "assign_owner": {"task_id": "018f2e3a-7000-7000-8000-000000000202", "owner_member_id": "018f2e3a-7000-7000-8000-000000000105"},
            "change_dependencies": {"task_id": "018f2e3a-7000-7000-8000-000000000202", "dependencies": []},
            "record_evidence": {"task_id": "018f2e3a-7000-7000-8000-000000000202", "evidence": [{"kind": "verifier", "reference_id": "verifier:1", "sha256": "a" * 64}]},
            "transition_task": {"task_id": "018f2e3a-7000-7000-8000-000000000202", "target_state": "ready"},
            "request_cancel": {"task_id": "018f2e3a-7000-7000-8000-000000000202", "reason": "Founder stopped this task."},
            "request_link_existing_task_run": {"task_id": "018f2e3a-7000-7000-8000-000000000202", "target_task_run_id": "018f2e3a-7000-7000-8000-000000000208"},
        }
        for operation, payload in cases.items():
            candidate = deepcopy(command)
            candidate["operation"] = operation
            candidate["expected_task_revision"] = 1
            candidate["payload"] = payload
            with self.subTest(operation=operation):
                self.assertEqual([], list(validator.iter_errors(candidate)))
                candidate["payload"]["task_run_id"] = "018f2e3a-7000-7000-8000-000000000208"
                self.assertNotEqual([], list(validator.iter_errors(candidate)))

    def test_critical_origin_terminal_and_criteria_guards(self) -> None:
        message = deepcopy(self._json(GOLDEN / "workgroup-message-v1" / "valid-agent-message.json"))
        message["agent_origin"] = None
        message_validator = self._validator("workgroup-message-v1.schema.json")
        self.assertNotEqual([], list(message_validator.iter_errors(message)))
        projection = deepcopy(self._json(GOLDEN / "workgroup-board-v1" / "valid-projection.json"))
        board_validator = self._validator("workgroup-board-v1.schema.json")
        for field, value in (("terminal_reason", None), ("acceptance_criteria_ref", None)):
            candidate = deepcopy(projection)
            candidate["tasks"][0][field] = value
            with self.subTest(field=field):
                self.assertNotEqual([], list(board_validator.iter_errors(candidate)))

    def test_message_reference_body_and_fingerprint_digests(self) -> None:
        for fixture in sorted((GOLDEN / "workgroup-message-v1").glob("valid-*.json")):
            message = self._json(fixture)
            self.assertIsInstance(message, dict)
            body = message["body"]
            fingerprint = message["canonical_fingerprint"]
            with self.subTest(fixture=fixture.name):
                self.assertEqual(
                    hashlib.sha256(body["text"].encode("utf-8")).hexdigest(),
                    body["sha256"],
                )
                self.assertEqual(
                    hashlib.sha256(self._canonical_message_bytes(message)).hexdigest(),
                    fingerprint["value"],
                )

    def test_board_projection_reference_digest(self) -> None:
        for fixture in sorted((GOLDEN / "workgroup-board-v1").glob("valid-projection*.json")):
            projection = self._json(fixture)
            with self.subTest(fixture=fixture.name):
                self.assertEqual(
                    hashlib.sha256(self._canonical_bytes(projection, "projection_digest")).hexdigest(),
                    projection["projection_digest"],
                )

    def _assert_vectors(self, schema_name: str, vector_dir: str) -> None:
        validator = self._validator(schema_name)
        files = sorted((GOLDEN / vector_dir).glob("*.json"))
        self.assertGreaterEqual(len(files), 4)
        for fixture in files:
            errors = list(validator.iter_errors(self._json(fixture)))
            with self.subTest(fixture=fixture.name):
                if fixture.name.startswith("valid-"):
                    self.assertEqual([], errors, errors)
                else:
                    self.assertNotEqual([], errors, "negative fixture unexpectedly validated")

    @staticmethod
    def _json(path: Path) -> object:
        return json.loads(path.read_text(encoding="utf-8"))

    def _validator(self, schema_name: str) -> Draft202012Validator:
        return Draft202012Validator(
            self._json(SCHEMAS / schema_name), format_checker=FormatChecker()
        )

    @classmethod
    def _canonical_message_bytes(cls, message: dict[str, object]) -> bytes:
        return cls._canonical_bytes(message, "canonical_fingerprint")

    @classmethod
    def _canonical_bytes(cls, document: dict[str, object], omitted_field: str) -> bytes:
        preimage = {key: value for key, value in document.items() if key != omitted_field}
        cls._require_canonical_types(preimage)
        return json.dumps(
            preimage, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    @classmethod
    def _require_canonical_types(cls, value: object) -> None:
        if value is None or type(value) in (str, bool):
            return
        if type(value) is int:
            if not 0 <= value <= 9007199254740991:
                raise ValueError("integer is outside the canonical JSON range")
            return
        if type(value) is list:
            for item in value:
                cls._require_canonical_types(item)
            return
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str or not key.isascii():
                    raise ValueError("canonical message keys must be ASCII strings")
                cls._require_canonical_types(item)
            return
        raise ValueError("canonical messages do not permit floats or other JSON values")


if __name__ == "__main__":
    unittest.main()
