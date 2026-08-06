import hashlib, inspect, unittest
from dataclasses import asdict, replace
from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.model import ClaimDisposition, FailureCodeV1, ReleaseFailure
class EvidenceTests(unittest.TestCase):
    def test_sol_bound_evidence_api_and_summary_are_exact(self) -> None:
        from scripts.release_v2.evidence import EvidenceSummary, validate_evidence

        self.assertEqual(tuple(inspect.signature(validate_evidence).parameters), ("records", "binding", "build_input", "qualification_subject", "advisory_report_raw", "structural_fixture"))
        records, binding, build, subject, raw = _bound()
        summary = _validate_bound(records, binding, build, subject, raw, fixture=True)
        self.assertEqual(summary.records, records)
        self.assertEqual(summary.evidence_sha256s, tuple(sorted(record.evidence_sha256 for record in records)))
        self.assertTrue(summary.structural_fixture)
        self.assertFalse(summary.production_trusted)
        self.assertFalse(hasattr(summary, "advisory_report_sha256"))
        digests = tuple(sorted(record.evidence_sha256 for record in records))
        self.assertFalse(EvidenceSummary(records, digests, True).production_trusted)
        for args in ((list(records), digests, True), ((object(),), digests, True), (records, list(digests), True), (records, (object(),), True), (records, digests, 1), (records, digests, True, 1), (records, digests, True, True)):
            with self.subTest(args=args):
                _blocks(self, lambda args=args: EvidenceSummary(*args), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_evidence_summary_rejects_empty_direct_construction(self) -> None:
        from scripts.release_v2.evidence import EvidenceSummary

        _blocks(self, lambda: EvidenceSummary((), (), True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_evidence_summary_has_no_dict_or_extra_attributes(self) -> None:
        from scripts.release_v2.evidence import EvidenceSummary

        records = _records()
        summary = EvidenceSummary(records, _summary_digests(records), True)
        self.assertFalse(hasattr(summary, "__dict__"))
        with self.assertRaises((AttributeError, TypeError)):
            summary.extra = "forbidden"

    def test_evidence_summary_rejects_noncanonical_direct_digest_tuple(self) -> None:
        from scripts.release_v2.evidence import EvidenceSummary

        records = _records()
        _blocks(self, lambda: EvidenceSummary(records, ("0" * 64,) * 6, True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_evidence_summary_rejects_duplicate_or_missing_direct_lane(self) -> None:
        from scripts.release_v2.evidence import EvidenceSummary

        records = _records()
        duplicate = _with_record(records, replace(records[0], producer_lane=records[1].producer_lane))
        _blocks(self, lambda: EvidenceSummary(duplicate, _summary_digests(duplicate), True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_sol_bound_evidence_rejects_non_exact_input_types_before_records(self) -> None:
        records, binding, build, subject, raw = _bound()
        for changed in ({"records": list(records)}, {"binding": object()}, {"build": object()}, {"subject": object()}, {"raw": bytearray(raw)}, {"fixture": 1}):
            with self.subTest(changed=changed):
                _blocks(self, lambda changed=changed: _validate_bound(changed.get("records", records), changed.get("binding", binding), changed.get("build", build), changed.get("subject", subject), changed.get("raw", raw), fixture=changed.get("fixture", True)), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_sol_bound_evidence_rejects_build_subject_digest_mismatch(self) -> None:
        records, binding, build, subject, raw = _bound()
        _blocks(self, lambda: _validate_bound(records, binding, replace(build, source_tree_sha256="0" * 64), subject, raw, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)
        _blocks(self, lambda: _validate_bound(records, binding, build, replace(subject, build_input_sha256="0" * 64), raw, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_sol_bound_evidence_recomputes_subject_and_binding_digests(self) -> None:
        records, binding, build, subject, raw = _bound()
        _blocks(self, lambda: _validate_bound(records, binding, build, replace(subject, subject_sha256="0" * 64), raw, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)
        _blocks(self, lambda: _validate_bound(records, replace(binding, subject_sha256="0" * 64), build, subject, raw, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)
        _blocks(self, lambda: _validate_bound(records, replace(binding, product_tuple_sha256="0" * 64), build, subject, raw, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)
        _blocks(self, lambda: _validate_bound((), replace(binding, source_sha256="0" * 64), build, subject, raw, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_sol_bound_evidence_rejects_profile_mismatches_before_records(self) -> None:
        _, binding, build, subject, raw = _bound()
        changed_build = replace(build, release_profile="debug")
        for changed_binding, changed_input, changed_subject in ((replace(binding, profile="debug"), build, subject), (binding, changed_build, _subject(changed_build, binding.product_tuple_sha256))):
            with self.subTest(binding=changed_binding.profile, build=changed_input.release_profile):
                _blocks(self, lambda changed_binding=changed_binding, changed_input=changed_input, changed_subject=changed_subject: _validate_bound((), changed_binding, changed_input, changed_subject, raw, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_sol_bound_evidence_binds_raw_advisory_and_build_epoch_freshness(self) -> None:
        records, binding, build, subject, raw = _bound()
        _blocks(self, lambda: _validate_bound(records, binding, build, subject, b"altered advisory report", fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)
        current = _with_record(records, replace(records[0], produced_at=10, fresh_until=11))
        _validate_bound(current, binding, build, subject, raw, fixture=True)
        stale = _with_record(records, replace(records[0], fresh_until=10))
        _blocks(self, lambda: _validate_bound(stale, binding, build, subject, raw, fixture=True), FailureCodeV1.EVIDENCE_STALE)

    def test_at_33_fixture_summary_binds_advisory_report_after_six_lanes(self) -> None:
        records, binding = _records(), _binding()
        summary = _validate(records, binding, fixture=True)
        self.assertEqual(len(summary.records), 6)
        self.assertFalse(summary.production_trusted)
        self.assertFalse(hasattr(summary, "advisory_validation_token"))
        self.assertFalse(hasattr(summary, "advisory_report_sha256"))

    def test_at_33_fixture_scan_is_structural_only(self) -> None:
        records, binding = _records(), _binding()
        summary = _validate(records, binding, fixture=True)
        self.assertTrue(summary.structural_fixture)
        self.assertFalse(summary.production_trusted)
        _blocks(self, lambda: _validate(records, binding), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_34_complete_hosted_lane_is_accepted_as_record(self) -> None:
        records, binding = _records(), _binding()
        summary = _validate(records, binding, fixture=True)
        self.assertEqual(len(summary.records), 6)
        _blocks(self, lambda: _validate(records[:-1], binding, fixture=True), FailureCodeV1.HOSTED_LANE_MISSING)

    def test_at_35_actual_hosted_attestation_is_typed(self) -> None:
        records, binding = _records(), _binding()
        self.assertEqual(records[0].checks[0].name, "artifact_digest")
        _blocks(self, lambda: _validate((replace(records[0], generation="PLANNED"),) + records[1:], binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)
        _blocks(self, lambda: _validate((replace(records[0], checks=records[0].checks[:-1]),) + records[1:], binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_36_subject_bound_evidence_is_accepted(self) -> None:
        records, binding = _records(), _binding()
        _validate(records, binding, fixture=True)
        for field in ("qualification_subject_sha256", "source_sha256", "product_tuple_sha256", "artifact_inventory_sha256", "platform", "profile", "tool_version", "producer_lane"):
            with self.subTest(field=field):
                value = "0" * 64 if field.endswith("sha256") else "wrong"
                _blocks(self, lambda field=field, value=value: _validate((replace(records[0], **{field: value}),) + records[1:], binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_36_advisory_digest_and_lane_tuple_are_exactly_bound(self) -> None:
        records, binding = _records(), _binding()
        _blocks(self, lambda: _validate(records, replace(binding, advisory_report_sha256="0" * 64), fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)
        for changed in ({"platform": "windows"}, {"producer_lane": "windows-pinned"}):
            with self.subTest(changed=changed):
                _blocks(self, lambda changed=changed: _validate((replace(records[0], **changed),) + records[1:], binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_36_advisory_check_cannot_move_from_linux_pinned_lane(self) -> None:
        records, binding = _records(), _binding()
        relocated = (_with_checks(records[0], records[0].checks[:-1]), _with_checks(records[1], records[1].checks + (records[0].checks[-1],))) + records[2:]
        _blocks(self, lambda: _validate(relocated, binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_advisory_report_binding_accepts_exact_opaque_bytes(self) -> None:
        raw = b"\xffadvisory\x00report"
        binding = _binding(hashlib.sha256(raw).hexdigest())
        _validate(_records(binding), binding, raw=raw, fixture=True)

    def test_advisory_report_binding_rejects_digest_mismatch(self) -> None:
        raw = b"advisory report"
        binding = _binding(hashlib.sha256(raw).hexdigest())
        _blocks(self, lambda: _validate(_records(binding), binding, raw=b"altered advisory report", fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_advisory_report_binding_rejects_malformed_raw_value(self) -> None:
        raw = b"advisory report"
        binding = _binding(hashlib.sha256(raw).hexdigest())
        for malformed in (bytearray(raw), "advisory report", None):
            with self.subTest(malformed=malformed):
                _blocks(self, lambda malformed=malformed: _validate(_records(binding), binding, raw=malformed, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_36_target_and_producer_mutations_fail_closed(self) -> None:
        records, binding = _records(), _binding()
        for changed in ({"target": "wrong"}, {"target": []}, {"producer": "wrong"}, {"producer": None}):
            with self.subTest(changed=changed):
                _blocks(self, lambda changed=changed: _validate((replace(records[0], **changed),) + records[1:], binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_37_unique_fresh_evidence_is_accepted(self) -> None:
        records, binding = _records(), _binding()
        _validate(records, binding, fixture=True)
        _blocks(self, lambda: _validate(records + (records[0],), binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)
        for changed, code in (({"produced_at": 11}, FailureCodeV1.EVIDENCE_STALE), ({"fresh_until": 10}, FailureCodeV1.EVIDENCE_STALE), ({"evidence_sha256": "0" * 64}, FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)):
            with self.subTest(changed=changed):
                _blocks(self, lambda changed=changed: _validate((replace(records[0], **changed),) + records[1:], binding, fixture=True), code)

    def test_at_38_independent_review_is_accepted_as_fixture_structure(self) -> None:
        records, binding = _records(), _binding()
        _validate(records, binding, fixture=True)
        review = replace(records[0].review, reviewer="Cafe\u0301", owner="Café")
        _blocks(self, lambda: _validate((replace(records[0], review=review),) + records[1:], binding, fixture=True), FailureCodeV1.SELF_APPROVAL_REJECTED)

    def test_at_38_review_mutations_are_typed_and_fail_closed(self) -> None:
        records, binding = _records(), _binding()
        for changed in ({"owner_role": "other_owner"}, {"owner_role": None}, {"reviewer_role": "other_reviewer"}, {"reviewer_role": []}, {"review_id": "review-2"}, {"review_id": ""}, {"owner": ""}, {"reviewer": "review er"}):
            with self.subTest(changed=changed):
                review = replace(records[0].review, **changed)
                _blocks(self, lambda review=review: _validate((replace(records[0], review=review),) + records[1:], binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)
        for review in (None, object()):
            with self.subTest(review=review):
                _blocks(self, lambda review=review: _validate((replace(records[0], review=review),) + records[1:], binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)

    def test_at_35_raw_check_never_raises_attribute_error(self) -> None:
        records, binding = _records(), _binding()
        for checks in (list(records[0].checks), records[0].checks + ("raw",), (object(),)):
            with self.subTest(checks=checks):
                malformed = replace(records[0], checks=checks)
                _blocks(self, lambda malformed=malformed: _validate((malformed,) + records[1:], binding, fixture=True), FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH)


def _binding(advisory_report_sha256=None):
    from scripts.release_v2.evidence import QualificationBindingV1

    build = _build()
    subject = _subject(build, "c" * 64)
    digest = hashlib.sha256(b"advisory report").hexdigest() if advisory_report_sha256 is None else advisory_report_sha256
    return QualificationBindingV1(subject.subject_sha256, "b" * 64, subject.product_tuple_sha256, "d" * 64, digest, "release")


def _records(binding=None):
    from scripts.release_v2.evidence import EvidenceCheckV1, EvidenceRecordV1, HostedLaneV1, ReviewBindingV1, qualification_binding_digest

    binding, records = (_binding() if binding is None else binding), []
    for index, (lane_id, platform, target, tool_version) in enumerate(HostedLaneV1.required_slots()):
        names = ("artifact_digest", "build", "clippy", "docs", "rustdoc", "tests") + (("advisory_report",) if index == 0 else ())
        checks = tuple(EvidenceCheckV1(name, binding.advisory_report_sha256 if name == "advisory_report" else hashlib.sha256(name.encode()).hexdigest(), "PASS") for name in names)
        record = EvidenceRecordV1(kind="hosted-qualification", schema_version="qualification-evidence.v1", qualification_subject_sha256=binding.subject_sha256, qualification_binding_sha256=qualification_binding_digest(binding), payload_sha256=_payload_digest(checks), producer="structural_fixture", produced_at=9, fresh_until=11, authenticity_method="STRUCTURAL_FIXTURE", environment_class="FIXTURE", outcome="PASS", source_sha256=binding.source_sha256, product_tuple_sha256=binding.product_tuple_sha256, artifact_inventory_sha256=binding.artifact_inventory_sha256, platform=platform, target=target, profile=binding.profile, tool_version=tool_version, generation="ACTUAL", producer_lane=lane_id, os_image_sha256="e" * 64, command_sha256="f" * 64, attestation_sha256="1" * 64, checks=checks, review=ReviewBindingV1("owner", "release_owner", "reviewer", "independent_reviewer", "review-1"), evidence_sha256="")
        records.append(replace(record, evidence_sha256=_digest(record)))
    return tuple(records)


def _digest(record) -> str:
    from scripts.release_v2.evidence import evidence_digest_payload

    return hashlib.sha256(canonical_json(evidence_digest_payload(record))).hexdigest()


def _summary_digests(records) -> tuple[str, ...]:
    return tuple(sorted(_digest(record) for record in records))


def _payload_digest(checks) -> str:
    from scripts.release_v2.evidence import payload_digest_payload

    return hashlib.sha256(canonical_json(payload_digest_payload(checks))).hexdigest()


def _with_checks(record, checks):
    unsigned = replace(record, checks=checks, payload_sha256=_payload_digest(checks), evidence_sha256="")
    return replace(unsigned, evidence_sha256=_digest(unsigned))


def _with_record(records, record):
    unsigned = replace(record, evidence_sha256="")
    return (replace(unsigned, evidence_sha256=_digest(unsigned)),) + records[1:]


def _bound():
    raw = b"advisory report"
    build, binding = _build(), _binding(hashlib.sha256(raw).hexdigest())
    subject = _subject(build, binding.product_tuple_sha256)
    return _records(binding), binding, build, subject, raw


def _validate_bound(records, binding, build, subject, raw, *, fixture=False):
    from scripts.release_v2.evidence import validate_evidence

    return validate_evidence(records, binding, build_input=build, qualification_subject=subject, advisory_report_raw=raw, structural_fixture=fixture)


def _build():
    from scripts.release_v2.model import BuildInputIdentityV2

    return BuildInputIdentityV2("build-input-v2", "a" * 40, "b" * 64, "1.0.0", "x86_64-unknown-linux-gnu", "linux", ("c" * 64,), "rust-1.97.1", "d" * 64, "e" * 64, "release", 10)


def _subject(build, product):
    from scripts.release_v2.model import QualificationSubjectIdentityV1

    build_sha256 = hashlib.sha256(canonical_json(asdict(build))).hexdigest()
    return QualificationSubjectIdentityV1(build_sha256, product, hashlib.sha256(canonical_json({"build_input_sha256": build_sha256, "product_tuple_sha256": product})).hexdigest())


def _validate(records, binding, *, raw=b"advisory report", fixture=False):
    from scripts.release_v2.evidence import validate_evidence

    build = _build()
    return validate_evidence(records, binding, build_input=build, qualification_subject=_subject(build, binding.product_tuple_sha256), advisory_report_raw=raw, structural_fixture=fixture)


def _blocks(case, callback, code):
    with case.assertRaises(ReleaseFailure) as raised:
        callback()
    case.assertIs(raised.exception.code, code)


class ClaimTests(unittest.TestCase):
    def test_at_39_fixture_claims_are_never_verified(self) -> None:
        from scripts.release_v2.claims import current_claim_matrix, validate_claim_matrix
        matrix = current_claim_matrix("a" * 64)
        self.assertNotIn("VERIFIED", (claim.disposition.value for claim in matrix.claims))
        _blocks(self, lambda: validate_claim_matrix((replace(matrix.claims[0], disposition=ClaimDisposition.VERIFIED),) + matrix.claims[1:], matrix.subject_sha256), FailureCodeV1.CLAIM_UNSUPPORTED)

    def test_at_40_each_known_claim_has_one_disposition(self) -> None:
        from scripts.release_v2.claims import current_claim_matrix, validate_claim_matrix
        matrix = current_claim_matrix("a" * 64)
        self.assertEqual(len(matrix.claims), 22)
        for malformed in (matrix.claims[:-1], (matrix.claims[0],) + matrix.claims, (replace(matrix.claims[0], claim_id="unknown_claim"),) + matrix.claims[1:], (replace(matrix.claims[0], disposition=ClaimDisposition.NOT_RUN),) + matrix.claims[1:]):
            _blocks(self, lambda malformed=malformed: validate_claim_matrix(malformed, matrix.subject_sha256), FailureCodeV1.CLAIM_UNSUPPORTED)

    def test_at_41_current_claim_statuses_match_contract(self) -> None:
        from scripts.release_v2.claims import current_claim_matrix
        actual = tuple((claim.claim_id, claim.disposition.value, claim.blocker_code.value if claim.blocker_code else None) for claim in current_claim_matrix("a" * 64).claims)
        expected = (("operational_telemetry", "BLOCKED", "EvidenceMissing"), ("macos_developer_id_signing", "BLOCKED_CREDENTIALS", "SigningBlockedCredentials"), ("notarization_stapling", "BLOCKED_CREDENTIALS", "SigningBlockedCredentials"), ("live_openai_l4", "NOT_RUN", None), ("tool_process_execution", "BLOCKED", "NATIVE_SANDBOX_NOT_QUALIFIED"), ("mcp_fixture_mode", "BLOCKED", "EvidenceMissing"), ("mcp_external_activation", "NOT_ACTIVATED", None), ("bundled_runtime", "NOT_ACTIVATED", "ArtifactMissing"), ("external_daemon", "NOT_RUN", None), ("v1_v2_compatibility", "BLOCKED", "EvidenceMissing"), ("recovery_upgrade", "NOT_RUN", None), ("install_upgrade_rollback", "NOT_RUN", None), ("linux_qualification", "BLOCKED_HOSTED_EVIDENCE", "HostedLaneMissing"), ("macos_qualification", "BLOCKED_HOSTED_EVIDENCE", "HostedLaneMissing"), ("windows_qualification", "BLOCKED_HOSTED_EVIDENCE", "HostedLaneMissing"), ("pinned_lane", "BLOCKED_HOSTED_EVIDENCE", "HostedLaneMissing"), ("msrv_lane", "BLOCKED_HOSTED_EVIDENCE", "HostedLaneMissing"), ("dependency_inventory", "BLOCKED", "DependencyInventoryIncomplete"), ("license", "BLOCKED", "LicenseEvidenceMissing"), ("advisory", "BLOCKED", "AdvisoryReportMissing"), ("sbom", "BLOCKED", "SbomIncomplete"), ("checksums", "BLOCKED", "ArtifactMissing"))
        self.assertEqual(actual, expected)

    def test_at_42_fixture_result_is_structural_valid_and_blocked_evidence(self) -> None:
        from scripts.release_v2.claims import current_claim_matrix, fixture_gate_result, production_gate_exit_code
        result = fixture_gate_result(current_claim_matrix("a" * 64))
        self.assertEqual((result.fixture_status.value, result.overall_status.value, result.production_approved, result.production_gate.disposition.value), ("STRUCTURAL_FIXTURE_VALID", "BLOCKED_EVIDENCE", False, "BLOCKED"))
        self.assertEqual(production_gate_exit_code(result), 1)
