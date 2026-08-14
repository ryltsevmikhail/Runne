import dataclasses
import hashlib
import importlib
import unittest
from pathlib import Path

from scripts.rc0_policy.canonical import canonical_bytes, loads_canonical
from scripts.rc0_policy import schemas as rc0_schemas
from scripts.tests.rc0_platform_envelope_support import (
    _NOW, _fixture_envelope, _fixture_schema_store, _schema_digest, _schema_documents, _sign, different_value,
    valid_fixture_envelope,
)


ROOT = Path(__file__).resolve().parents[2]
EXTERNAL_SCHEMA = ROOT / "docs/schemas/rc0-external-signed-envelope-v1.schema.json"


def external_schema_errors(value: object) -> tuple[str, ...]:
    schema = loads_canonical(EXTERNAL_SCHEMA.read_bytes())
    return tuple(rc0_schemas._validate(value, schema, schema, "$"))


def envelope_module():
    try:
        return importlib.import_module("scripts.rc0_policy.external_envelope")
    except ModuleNotFoundError as error:
        raise AssertionError("external signed-envelope verifier is absent") from error


class EnvelopeTests(unittest.TestCase):
    def verify(self, raw: bytes, verifier: object | None = None):
        module = envelope_module()
        if verifier is None:
            _, verifier = valid_fixture_envelope()
        return module.verify_signed_envelope(raw, _fixture_schema_store(), verifier, _NOW)

    def assert_failure(self, raw: bytes, code: str, verifier: object | None = None) -> None:
        module = envelope_module()
        with self.assertRaises(module.EnvelopeFailure) as raised:
            self.verify(raw, verifier)
        self.assertEqual(raised.exception.code, code)

    def test_transcript_frames_domain_and_unsigned_envelope(self) -> None:
        module = envelope_module()
        envelope = _fixture_envelope()
        envelope.pop("signature")
        unsigned = canonical_bytes(envelope)
        transcript = module.signature_transcript(envelope)
        domain = b"gocode.external-signed-envelope/1"
        self.assertEqual(transcript, len(domain).to_bytes(4, "big") + domain + len(unsigned).to_bytes(8, "big") + unsigned)

    def test_fixture_uses_rfc3339_utc_times_and_validates_full_envelope_schema(self) -> None:
        envelope = _fixture_envelope()
        self.assertTrue(all(type(envelope[field]) is str and envelope[field].endswith("Z") for field in ("issued_at", "not_before", "expires_at")))
        self.assertEqual(external_schema_errors(loads_canonical(_sign(envelope))), ())

    def test_mutating_each_metadata_field_invalidates_signature(self) -> None:
        raw, verifier = valid_fixture_envelope()
        original = loads_canonical(raw)
        for field in (
            "issuer", "issuer_key_id", "issuer_key_epoch", "issuer_subject_id",
            "issuer_controlling_account_id", "issuer_delegated_session_id", "issuer_lane_id",
            "issuer_role", "issuer_revocation_epoch", "signature_profile_id", "issued_at",
            "not_before", "expires_at",
        ):
            mutated = dict(original)
            mutated[field] = different_value(field, mutated[field])
            with self.subTest(field=field):
                expected = "FIXTURE_GUARD" if field in {"issuer", "signature_profile_id"} else (
                    "TIME_INVALID" if field == "issued_at" else "TRUST_MISMATCH"
                )
                self.assert_failure(canonical_bytes(mutated), expected, verifier)

    def test_rejects_detached_or_payload_digest_substitution(self) -> None:
        for field, value in (("payload", "cas:sha256:" + "0" * 64), ("payload_sha256", "0" * 64)):
            envelope = _fixture_envelope()
            envelope[field] = value
            with self.subTest(field=field):
                self.assert_failure(_sign(envelope), "PAYLOAD_DIGEST_MISMATCH")

    def test_rejects_unknown_schema_issuer_role_epoch_and_profile(self) -> None:
        for field, value, code in (
            ("payload_schema_id", "unknown", "SCHEMA_INVALID"),
            ("issuer", "other", "FIXTURE_GUARD"),
            ("issuer_role", "", "METADATA_INVALID"),
            ("issuer_key_epoch", -1, "METADATA_INVALID"),
            ("signature_profile_id", "other", "FIXTURE_GUARD"),
        ):
            envelope = _fixture_envelope()
            envelope[field] = value
            with self.subTest(field=field):
                self.assert_failure(_sign(envelope), code)

    def test_rejects_bom_duplicate_key_depth_size_and_noncanonical_bytes(self) -> None:
        raw, _ = valid_fixture_envelope()
        duplicate = raw.replace(b'"issuer":', b'"issuer":"other","issuer":', 1)
        for candidate in (b"\xef\xbb\xbf" + raw, duplicate, b'{"x":' * 33 + b"0" + b"}" * 33, b" " + raw):
            with self.subTest(prefix=candidate[:10]):
                self.assert_failure(candidate, "PARSE_INVALID")

    def test_rejects_boolean_or_always_true_trust_callback(self) -> None:
        raw, _ = valid_fixture_envelope()
        for callback in (lambda *_: True, lambda *_: object()):
            with self.subTest(callback=callback):
                self.assert_failure(raw, "TRUST_INVALID", callback)

    def test_fixture_signature_can_never_satisfy_production_profile(self) -> None:
        envelope = _fixture_envelope()
        envelope["signature_profile_id"] = "PRODUCTION"
        self.assert_failure(_sign(envelope), "FIXTURE_GUARD")

    def test_mutating_parser_output_cannot_change_verified_payload_or_transcript(self) -> None:
        module = envelope_module()
        raw, verifier = valid_fixture_envelope()
        parsed = loads_canonical(raw)
        verified = self.verify(raw, verifier)
        parsed["payload"]["fixture"] = "mutated"
        self.assertEqual(verified.payload_canonical_bytes, canonical_bytes(_fixture_envelope()["payload"]))
        signed = loads_canonical(raw)
        self.assertEqual(verified.trust.transcript_sha256, hashlib.sha256(module.signature_transcript({key: signed[key] for key in signed if key != "signature"})).hexdigest())

    def test_rejects_directly_constructed_or_field_replaced_verified_envelope(self) -> None:
        module = envelope_module()
        raw, verifier = valid_fixture_envelope()
        verified = self.verify(raw, verifier)
        with self.assertRaises(TypeError):
            module.VerifiedEnvelope()
        with self.assertRaises(TypeError):
            dataclasses.replace(verified, issuer="other")

    def test_verified_envelope_is_opaque_immutable_and_fixture_only(self) -> None:
        module = envelope_module()
        raw, verifier = valid_fixture_envelope()
        verified = self.verify(raw, verifier)
        self.assertEqual(module.principal_binding(verified).role_id, "FIXTURE_ADJUNCT_REGISTRY_TEST_ONLY")
        self.assertIsNone(module.require_fixture_verified(verified))
        self.assertEqual(verified.payload_sha256, hashlib.sha256(verified.payload_canonical_bytes).hexdigest())
        self.assertEqual(verified.envelope_sha256, hashlib.sha256(raw).hexdigest())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            verified.issuer = "changed"
        self.assertEqual(len(loads_canonical(raw)), 19)

    def test_verified_envelope_rejects_every_retained_field_drift(self) -> None:
        module = envelope_module()
        verified = self.verify(valid_fixture_envelope()[0])
        for field in verified.__dataclass_fields__:
            if field == "_verification_token":
                continue
            original = getattr(verified, field)
            replacement = b"drift" if type(original) is bytes else (original + 1 if type(original) is int else object())
            object.__setattr__(verified, field, replacement)
            with self.subTest(field=field):
                with self.assertRaises(module.EnvelopeFailure) as raised:
                    module.principal_binding(verified)
                self.assertEqual(raised.exception.code, "VERIFIED_INVALID")
            object.__setattr__(verified, field, original)

    def test_fixture_verified_envelope_is_rejected_by_every_production_boundary(self) -> None:
        module = envelope_module()
        raw, verifier = valid_fixture_envelope()
        module.require_fixture_verified(self.verify(raw, verifier))
        self.assertEqual(module.PRODUCTION_BOUNDARY_ENTRYPOINTS, ())

    def test_rejects_invalid_time_interval_and_expired_envelope(self) -> None:
        invalid = _fixture_envelope()
        invalid["not_before"] = "2023-11-14T22:13:21Z"
        self.assert_failure(_sign(invalid), "TIME_INVALID")
        expired = _fixture_envelope()
        expired["expires_at"] = "2023-11-14T22:13:19Z"
        self.assert_failure(_sign(expired), "TIME_INVALID")

    def test_rejects_an_envelope_issued_after_now(self) -> None:
        future = _fixture_envelope()
        future["issued_at"] = "2023-11-14T22:13:21Z"
        self.assert_failure(_sign(future), "TIME_INVALID")

    def test_strict_adjunct_store_rejects_invalid_anyof_values(self) -> None:
        module = envelope_module()
        store = module.AdjunctSchemaStore(_schema_documents())
        schema_id = "gocode.rc0.policy-activation-intent/1"
        value = {
            "schema_version": schema_id, "repository_id": "gocode",
            "activation_id": "01234567-0123-7123-8123-0123456789ab", "activation_action": "activate",
            "mapping_policy_envelope_sha256": "0" * 64, "adjunct_trust_registry_envelope_sha256": "1" * 64,
            "adjunct_trust_registry_payload_sha256": "2" * 64, "rc0_qualification_policy_digest": "3" * 64,
            "shared_decision_payload_sha256": "4" * 64, "activation_epoch": 1,
            "predecessor_activation_snapshot_envelope_sha256": None, "signature_key_epoch": 0,
            "revocation_epoch": 0, "runner_consumer_subject_id": "runner",
            "downstream_consumer_subject_id": "consumer", "not_before": "2023-11-14T22:13:10Z",
            "activation_deadline": "2023-11-14T22:13:30Z",
        }
        store.validate(schema_id, _schema_digest(schema_id), value)
        for invalid in (False, {}):
            with self.subTest(invalid=invalid):
                changed = dict(value, predecessor_activation_snapshot_envelope_sha256=invalid)
                with self.assertRaises(module.EnvelopeFailure) as raised:
                    store.validate(schema_id, _schema_digest(schema_id), changed)
                self.assertEqual(raised.exception.code, "SCHEMA_INVALID")

    def test_rejects_non_rfc3339_utc_timestamp_encodings(self) -> None:
        for field, value in (
            ("issued_at", _NOW), ("not_before", "2023-11-14T22:13:10+00:00"),
            ("expires_at", "2023-11-14T22:13:30.1Z"),
        ):
            with self.subTest(field=field):
                envelope = _fixture_envelope()
                envelope[field] = value
                self.assert_failure(_sign(envelope), "METADATA_INVALID")


if __name__ == "__main__":
    unittest.main()
