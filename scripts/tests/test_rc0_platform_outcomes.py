"""Outcome normalization requires a digest-bound operational trust result."""

from __future__ import annotations

import hashlib
import unittest

from scripts.rc0_policy.outcomes import (
    OUTCOME_TRUST_DOMAIN,
    OperationalTrustVerification,
    OperationalVerificationError,
    VerifiedRequiredGateResults,
    normalize_required_gate_results,
    normalize_verified_required_gate_results,
    verify_required_gate_results,
)


_BINDING = {"policy_digest": "a" * 64}


def _gate(gate_id: str, outcome: str = "PASS") -> dict[str, object]:
    result, reason = {
        "PASS": ("PASS", None),
        "FAIL": ("BLOCKED", "REQUIRED_GATE_FAILED"),
        "NOT_RUN": ("BLOCKED", "REQUIRED_GATE_NOT_RUN"),
    }[outcome]
    gate = {
        "gate_id": gate_id, "stage": "SOURCE_CANDIDATE",
        "execution_outcome": outcome, "gate_result": result,
        "binding": dict(_BINDING),
    }
    if reason is not None:
        gate["blocked_reason"] = reason
    return gate


def _trusted(_: object, transcript: bytes) -> OperationalTrustVerification:
    snapshot = transcript.removeprefix(OUTCOME_TRUST_DOMAIN)
    return OperationalTrustVerification(
        "FIXTURE_ONLY", hashlib.sha256(transcript).hexdigest(),
        hashlib.sha256(snapshot).hexdigest(),
    )


class OutcomeNormalizationTests(unittest.TestCase):
    def test_trust_failure_is_nonzero_and_emits_no_normalized_artifact(self) -> None:
        def reject_trust(_: object, __: bytes) -> OperationalTrustVerification:
            raise ValueError("TRUST_INVALID")

        with self.assertRaises(OperationalVerificationError) as raised:
            normalize_required_gate_results([_gate("source")], ("source",), _BINDING, reject_trust)
        self.assertEqual((raised.exception.code, raised.exception.exit_code), ("TRUST_INVALID", 1))

    def test_operational_failures_never_normalize_gate_results(self) -> None:
        for code in (
            "PARSE_INVALID", "SCHEMA_INVALID", "SIGNATURE_INVALID", "TRUST_INVALID",
            "ROLLBACK_INVALID", "ROLE_SEPARATION_INVALID",
        ):
            with self.subTest(code=code):
                with self.assertRaises(OperationalVerificationError) as raised:
                    normalize_required_gate_results(
                        [_gate("source")], ("source",), _BINDING,
                        lambda *_: (_ for _ in ()).throw(ValueError(code)),
                    )
                self.assertEqual(raised.exception.code, code)

    def test_verified_gate_results_map_to_exact_rc0_blocked_codes(self) -> None:
        cases = (
            ([_gate("source", "FAIL")], "BLOCKED(REQUIRED_GATE_FAILED)"),
            ([_gate("source", "NOT_RUN")], "BLOCKED(REQUIRED_GATE_NOT_RUN)"),
            ([_gate("other")], "BLOCKED(REQUIRED_GATE_MISMATCH)"),
            ([_gate("source"), _gate("source")], "BLOCKED(REQUIRED_GATE_MISMATCH)"),
            ([_gate("source")], "PASS"),
        )
        for results, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    normalize_required_gate_results(results, ("source",), _BINDING, _trusted), expected,
                )

    def test_verified_binding_mismatch_maps_to_mismatch(self) -> None:
        self.assertEqual(
            normalize_required_gate_results([_gate("source")], ("source",), {"policy_digest": "b" * 64}, _trusted),
            "BLOCKED(REQUIRED_GATE_MISMATCH)",
        )

    def test_outcome_callback_noop_bool_or_none_fails(self) -> None:
        for response in (None, False, True, object(), {"verification_domain": "FIXTURE_ONLY"}):
            with self.subTest(response=type(response).__name__):
                with self.assertRaises(OperationalVerificationError) as raised:
                    verify_required_gate_results([_gate("source")], lambda *_: response)
                self.assertEqual(raised.exception.code, "OPERATIONAL_TRUST_INVALID")

    def test_outcome_callback_mutation_or_race_fails(self) -> None:
        def mutate(snapshot: object, _: bytes) -> OperationalTrustVerification:
            snapshot[0]["gate_result"] = "BLOCKED"  # type: ignore[index]
            return _trusted(snapshot, b"")

        with self.assertRaises(OperationalVerificationError) as raised:
            verify_required_gate_results([_gate("source")], mutate)
        self.assertEqual(raised.exception.code, "OPERATIONAL_TRUST_INVALID")

        raw = [_gate("source")]

        def race(snapshot: object, transcript: bytes) -> OperationalTrustVerification:
            raw[0]["execution_outcome"] = "FAIL"
            raw[0]["gate_result"] = "BLOCKED"
            raw[0]["blocked_reason"] = "REQUIRED_GATE_FAILED"
            return _trusted(snapshot, transcript)

        with self.assertRaises(OperationalVerificationError) as raised:
            verify_required_gate_results(raw, race)
        self.assertEqual(raised.exception.code, "REQUIRED_GATE_RACE_INVALID")

    def test_gate_shape_stage_outcome_result_reason_binding_fail_before_minting(self) -> None:
        cases = []
        for key, value in (
            ("stage", "RELEASE_APPROVAL"), ("execution_outcome", "UNKNOWN"),
            ("gate_result", "BLOCKED"), ("binding", []),
        ):
            changed = _gate("source")
            changed[key] = value
            cases.append(changed)
        missing_reason = _gate("source", "FAIL")
        missing_reason.pop("blocked_reason")
        extra_reason = _gate("source")
        extra_reason["blocked_reason"] = "REQUIRED_GATE_FAILED"
        extra_field = _gate("source")
        extra_field["extra"] = "forbidden"
        cases.extend((missing_reason, extra_reason, extra_field))
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(OperationalVerificationError) as raised:
                    verify_required_gate_results([raw], _trusted)
                self.assertEqual(raised.exception.code, "REQUIRED_GATE_SHAPE_INVALID")

    def test_verified_view_exposes_no_token_or_replay_path(self) -> None:
        verified = verify_required_gate_results([_gate("source")], _trusted)
        self.assertFalse(hasattr(verified, "_token"))
        with self.assertRaises(TypeError):
            VerifiedRequiredGateResults()
        replay = object.__new__(VerifiedRequiredGateResults)
        with self.assertRaises(OperationalVerificationError) as raised:
            normalize_verified_required_gate_results(replay, ("source",), _BINDING)
        self.assertEqual(raised.exception.code, "VERIFIED_RESULTS_INVALID")


if __name__ == "__main__":
    unittest.main()
