import hashlib
import unicodedata
from dataclasses import asdict, dataclass

from scripts.release_v2.canonical import canonical_json, validate_sha256
from scripts.release_v2.model import BuildInputIdentityV2, FailureCodeV1, QualificationSubjectIdentityV1, ReleaseFailure


_CHECKS = ("artifact_digest", "build", "clippy", "docs", "rustdoc", "tests")
_ADVISORY_CHECK = "advisory_report"
_SLOTS = (
    ("linux-pinned", "linux", "x86_64-unknown-linux-gnu", "rust-1.97.1"),
    ("linux-msrv", "linux", "x86_64-unknown-linux-gnu", "rust-1.95.0"),
    ("macos-pinned", "macos", "aarch64-apple-darwin", "rust-1.97.1"),
    ("macos-msrv", "macos", "aarch64-apple-darwin", "rust-1.95.0"),
    ("windows-pinned", "windows", "x86_64-pc-windows-msvc", "rust-1.97.1"),
    ("windows-msrv", "windows", "x86_64-pc-windows-msvc", "rust-1.95.0"),
)


@dataclass(frozen=True)
class QualificationBindingV1:
    subject_sha256: str
    source_sha256: str
    product_tuple_sha256: str
    artifact_inventory_sha256: str
    advisory_report_sha256: str
    profile: str


@dataclass(frozen=True)
class EvidenceCheckV1:
    name: str
    digest: str
    result: str


@dataclass(frozen=True)
class ReviewBindingV1:
    owner: str
    owner_role: str
    reviewer: str
    reviewer_role: str
    review_id: str


@dataclass(frozen=True)
class EvidenceRecordV1:
    kind: str
    schema_version: str
    qualification_subject_sha256: str
    qualification_binding_sha256: str
    payload_sha256: str
    producer: str
    produced_at: int
    fresh_until: int
    authenticity_method: str
    environment_class: str
    outcome: str
    source_sha256: str
    product_tuple_sha256: str
    artifact_inventory_sha256: str
    platform: str
    target: str
    profile: str
    tool_version: str
    generation: str
    producer_lane: str
    os_image_sha256: str
    command_sha256: str
    attestation_sha256: str
    checks: tuple[EvidenceCheckV1, ...]
    review: ReviewBindingV1
    evidence_sha256: str


@dataclass(frozen=True)
class HostedLaneV1:
    lane_id: str
    platform: str
    target: str
    tool_version: str

    @classmethod
    def required_slots(cls) -> tuple[tuple[str, str, str, str], ...]:
        return _SLOTS


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    records: tuple[EvidenceRecordV1, ...]
    evidence_sha256s: tuple[str, ...]
    structural_fixture: bool
    production_trusted: bool = False

    def __post_init__(self) -> None:
        if type(self.records) is not tuple or not all(type(item) is EvidenceRecordV1 for item in self.records):
            raise _mismatch()
        if type(self.evidence_sha256s) is not tuple or not all(type(item) is str for item in self.evidence_sha256s):
            raise _mismatch()
        if type(self.structural_fixture) is not bool or type(self.production_trusted) is not bool or not self.structural_fixture or self.production_trusted:
            raise _mismatch()
        lane_ids = tuple(item.producer_lane for item in self.records)
        expected_lane_ids = {slot[0] for slot in _SLOTS}
        if len(self.records) != len(_SLOTS) or not all(type(lane_id) is str for lane_id in lane_ids) or len(set(lane_ids)) != len(lane_ids) or set(lane_ids) != expected_lane_ids:
            raise _mismatch()
        digests = tuple(sorted(hashlib.sha256(canonical_json(evidence_digest_payload(item))).hexdigest() for item in self.records))
        if self.evidence_sha256s != digests:
            raise _mismatch()


def qualification_binding_payload(binding: QualificationBindingV1) -> dict[str, object]:
    return {
        "advisory_report_sha256": binding.advisory_report_sha256,
        "artifact_inventory_sha256": binding.artifact_inventory_sha256,
        "profile": binding.profile,
        "product_tuple_sha256": binding.product_tuple_sha256,
        "source_sha256": binding.source_sha256,
        "subject_sha256": binding.subject_sha256,
    }


def qualification_binding_digest(binding: QualificationBindingV1) -> str:
    return hashlib.sha256(canonical_json(qualification_binding_payload(binding))).hexdigest()


def payload_digest_payload(checks: tuple[EvidenceCheckV1, ...]) -> dict[str, object]:
    return {"checks": [{"digest": item.digest, "name": item.name, "result": item.result} for item in checks]}


def evidence_digest_payload(record: EvidenceRecordV1) -> dict[str, object]:
    return {field: value for field, value in asdict(record).items() if field != "evidence_sha256"}


def validate_evidence(records: tuple[EvidenceRecordV1, ...], binding: QualificationBindingV1, *, build_input: BuildInputIdentityV2, qualification_subject: QualificationSubjectIdentityV1, advisory_report_raw: bytes, structural_fixture: bool = False) -> EvidenceSummary:
    if type(records) is not tuple or type(binding) is not QualificationBindingV1 or type(build_input) is not BuildInputIdentityV2 or type(qualification_subject) is not QualificationSubjectIdentityV1 or type(advisory_report_raw) is not bytes or type(structural_fixture) is not bool:
        raise _mismatch()
    _binding(binding)
    _bound_inputs(binding, build_input, qualification_subject, advisory_report_raw)
    if not structural_fixture:
        raise _mismatch()
    seen_ids: set[tuple[str, str, str]] = set()
    seen_digests: set[str] = set()
    slots: set[tuple[str, str, str, str]] = set()
    advisory_bindings = 0
    for record in records:
        advisory_bindings += _record(record, binding, build_input.source_date_epoch)
        identity = (record.qualification_subject_sha256, record.producer_lane, record.payload_sha256)
        slot = (record.producer_lane, record.platform, record.target, record.tool_version)
        if identity in seen_ids or record.evidence_sha256 in seen_digests or slot in slots:
            raise _mismatch()
        seen_ids.add(identity)
        seen_digests.add(record.evidence_sha256)
        slots.add(slot)
    if slots != set(_SLOTS):
        raise ReleaseFailure(FailureCodeV1.HOSTED_LANE_MISSING, "hosted_lanes_missing")
    if advisory_bindings != 1:
        raise _mismatch()
    return EvidenceSummary(records, tuple(sorted(seen_digests)), True)


def _binding(value: QualificationBindingV1) -> None:
    if not _text(value.profile) or not all(_digest(item) for item in (value.subject_sha256, value.source_sha256, value.product_tuple_sha256, value.artifact_inventory_sha256, value.advisory_report_sha256)):
        raise _mismatch()


def _bound_inputs(binding: QualificationBindingV1, build: BuildInputIdentityV2, subject: QualificationSubjectIdentityV1, advisory_report_raw: bytes) -> None:
    build_sha256 = hashlib.sha256(canonical_json(asdict(build))).hexdigest()
    subject_sha256 = hashlib.sha256(canonical_json({"build_input_sha256": subject.build_input_sha256, "product_tuple_sha256": subject.product_tuple_sha256})).hexdigest()
    if build_sha256 != subject.build_input_sha256 or binding.source_sha256 != build.source_tree_sha256 or binding.profile != build.release_profile or subject.subject_sha256 != subject_sha256 or (binding.subject_sha256, binding.product_tuple_sha256) != (subject.subject_sha256, subject.product_tuple_sha256) or hashlib.sha256(advisory_report_raw).hexdigest() != binding.advisory_report_sha256:
        raise _mismatch()


def _record(value: object, binding: QualificationBindingV1, now: int) -> int:
    if type(value) is not EvidenceRecordV1 or value.kind != "hosted-qualification" or value.schema_version != "qualification-evidence.v1" or value.producer != "structural_fixture" or value.authenticity_method != "STRUCTURAL_FIXTURE" or value.environment_class != "FIXTURE" or value.outcome != "PASS" or value.generation != "ACTUAL":
        raise _mismatch()
    if type(value.produced_at) is not int or type(value.fresh_until) is not int or value.produced_at < 0 or value.produced_at > now or value.fresh_until <= now:
        raise _stale()
    if (value.qualification_subject_sha256, value.qualification_binding_sha256, value.source_sha256, value.product_tuple_sha256, value.artifact_inventory_sha256, value.profile) != (binding.subject_sha256, qualification_binding_digest(binding), binding.source_sha256, binding.product_tuple_sha256, binding.artifact_inventory_sha256, binding.profile):
        raise _mismatch()
    if (value.producer_lane, value.platform, value.target, value.tool_version) not in _SLOTS:
        raise _mismatch()
    if not all(_digest(item) for item in (value.payload_sha256, value.os_image_sha256, value.command_sha256, value.attestation_sha256)):
        raise _mismatch()
    advisory_binding = _checks(value.checks, value.payload_sha256, binding.advisory_report_sha256, value.producer_lane)
    _review(value.review)
    if not _digest(value.evidence_sha256) or value.evidence_sha256 != hashlib.sha256(canonical_json(evidence_digest_payload(value))).hexdigest():
        raise _mismatch()
    return advisory_binding


def _checks(value: object, payload_sha256: str, advisory_sha256: str, producer_lane: str) -> int:
    if type(value) is not tuple or not all(type(item) is EvidenceCheckV1 for item in value):
        raise _mismatch()
    names = tuple(item.name for item in value)
    required_names = _CHECKS + ((_ADVISORY_CHECK,) if producer_lane == "linux-pinned" else ())
    if names != required_names:
        raise _mismatch()
    if any(item.result != "PASS" or not _digest(item.digest) for item in value):
        raise _mismatch()
    if payload_sha256 != hashlib.sha256(canonical_json(payload_digest_payload(value))).hexdigest():
        raise _mismatch()
    if names[-1:] == (_ADVISORY_CHECK,):
        if value[-1].digest != advisory_sha256:
            raise _mismatch()
        return 1
    return 0


def _review(value: object) -> None:
    if type(value) is not ReviewBindingV1:
        raise _mismatch()
    if type(value.owner) is str and type(value.reviewer) is str and unicodedata.normalize("NFC", value.owner) == unicodedata.normalize("NFC", value.reviewer):
        raise ReleaseFailure(FailureCodeV1.SELF_APPROVAL_REJECTED, "self_approval_rejected")
    if not all(_text(item) for item in (value.owner, value.owner_role, value.reviewer, value.reviewer_role, value.review_id)):
        raise _mismatch()
    if value.owner_role == value.reviewer_role:
        raise ReleaseFailure(FailureCodeV1.SELF_APPROVAL_REJECTED, "self_approval_rejected")


def _digest(value: object) -> bool:
    try:
        validate_sha256(value)
        return True
    except ReleaseFailure:
        return False


def _text(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= 200 and unicodedata.normalize("NFC", value) == value and not any(character.isspace() for character in value)


def _mismatch() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH, "evidence_candidate_mismatch")


def _stale() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.EVIDENCE_STALE, "evidence_stale")
