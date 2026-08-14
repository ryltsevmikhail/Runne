import json
import pathlib
import unittest
from copy import deepcopy

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = pathlib.Path(__file__).parents[2]
SCHEMAS = ROOT / "docs/schemas"
FIXTURES = ROOT / "crates/gocode-release-authority/tests/fixtures"


def load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class PublicationEffectSchemaGoldenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.intent_schema = load(SCHEMAS / "publication-effect-intent-v1.schema.json")
        cls.settlement_schema = load(SCHEMAS / "publication-effect-settlement-v1.schema.json")
        cls.ledger_schema = load(SCHEMAS / "publication-effect-ledger-v1.schema.json")
        registry = Registry().with_resource(
            cls.intent_schema["$id"], Resource.from_contents(cls.intent_schema)
        ).with_resource(
            "publication-effect-intent-v1.schema.json", Resource.from_contents(cls.intent_schema)
        ).with_resource(
            "gocode.release.publication-effect-ledger/publication-effect-intent-v1.schema.json",
            Resource.from_contents(cls.intent_schema),
        )
        cls.validators = {
            "intent": Draft202012Validator(cls.intent_schema, registry=registry),
            "settlement": Draft202012Validator(cls.settlement_schema, registry=registry),
            "ledger": Draft202012Validator(cls.ledger_schema, registry=registry),
        }
        cls.values = {
            name: load(FIXTURES / f"publication_effect_{name}_v1.json")
            for name in cls.validators
        }

    def reject(self, name: str, value: dict, label: str) -> None:
        self.assertTrue(list(self.validators[name].iter_errors(value)), label)

    def test_full_rust_golden_documents_validate(self) -> None:
        for name, validator in self.validators.items():
            with self.subTest(name=name):
                self.assertFalse(list(validator.iter_errors(self.values[name])))

    def test_missing_every_required_field_and_unknown_fields_are_rejected(self) -> None:
        for name, schema in ((name, getattr(self, f"{name}_schema")) for name in self.validators):
            for field in schema["required"]:
                value = deepcopy(self.values[name]); value.pop(field)
                self.reject(name, value, f"{name}.missing.{field}")
            value = deepcopy(self.values[name]); value["unknown"] = True
            self.reject(name, value, f"{name}.unknown")
        ledger = self.values["ledger"]
        paths = {
            "claim": lambda value: value["claims"][0],
            "claim.intent": lambda value: value["claims"][0]["intent"],
            "claim.intent.executor": lambda value: value["claims"][0]["intent"]["executor"],
            "record": lambda value: value["claims"][0]["commands"][0],
            "command": lambda value: value["claims"][0]["commands"][0]["command"],
            "command.intent": lambda value: value["claims"][0]["commands"][0]["command"]["intent"],
            "outcome": lambda value: value["claims"][0]["commands"][0]["outcome"],
        }
        for label, locate in paths.items():
            for field in locate(ledger):
                value = deepcopy(ledger); cursor = locate(value); cursor.pop(field)
                self.reject("ledger", value, f"{label}.missing.{field}")
            value = deepcopy(ledger); cursor = locate(value)
            cursor["unknown"] = True
            self.reject("ledger", value, label)

    def test_invalid_digests_identities_generations_types_and_enums_are_rejected(self) -> None:
        intent_cases = {
            "digest": ("candidate_sha256", "A" * 64),
            "identity": ("promotion", "bad value"),
            "generation": ("generation", 0),
            "wrong_type": ("allowlist_generation", "1"),
        }
        for label, (field, replacement) in intent_cases.items():
            value = deepcopy(self.values["intent"]); value[field] = replacement
            self.reject("intent", value, label)
        value = deepcopy(self.values["intent"]); value["executor"]["key_id"] = "bad value"
        self.reject("intent", value, "executor identity")
        settlement_cases = {
            "digest": ("executable_sha256", "0" * 63),
            "namespace": ("idempotency_namespace", "bad value"),
            "generation": ("generation", 0),
            "enum": ("observed_result", "unknown"),
            "type": ("generation", True),
        }
        for label, (field, replacement) in settlement_cases.items():
            value = deepcopy(self.values["settlement"]); value[field] = replacement
            self.reject("settlement", value, label)
        for label, mutate in {
            "state": lambda value: value["claims"][0].update(state="authorized"),
            "fingerprint": lambda value: value["claims"][0]["commands"][0].update(command_fingerprint_sha256="A" * 64),
            "generation": lambda value: value["claims"][0]["commands"][0]["outcome"].update(generation=0),
            "kind": lambda value: value["claims"][0]["commands"][0]["command"].update(kind="unknown"),
            "type": lambda value: value["claims"][0].update(reconciliations="0"),
        }.items():
            value = deepcopy(self.values["ledger"]); mutate(value); self.reject("ledger", value, label)


if __name__ == "__main__":
    unittest.main()
