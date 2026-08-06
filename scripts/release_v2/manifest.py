import hashlib
from dataclasses import asdict, dataclass

from scripts.release_v2.advisories import AdvisoryValidationPolicy, validate_advisory_report
from scripts.release_v2.archive import ArchiveIndexV1
from scripts.release_v2.canonical import canonical_json, parse_canonical_json, validate_sha256
from scripts.release_v2.claims import ClaimMatrixV1, current_claim_matrix, validate_claim_matrix
from scripts.release_v2.dependencies_types import DependencyInventoryV1
from scripts.release_v2.evidence import EvidenceRecordV1, EvidenceSummary, QualificationBindingV1, validate_evidence
from scripts.release_v2.inventory import checksum_rows, parse_checksums
from scripts.release_v2.licenses import LicensePolicyRecordV1, validate_license_report
from scripts.release_v2.model import ArtifactEntry, ArtifactInventoryV2, BuildInputIdentityV2, FailureCodeV1, ProductTupleIdentityV1, QualificationSubjectIdentityV1, ReleaseCandidateIdentityV2, ReleaseFailure
from scripts.release_v2.sbom import validate_sbom


_FIELDS = frozenset({"artifact_inventory_sha256", "build_input_sha256", "candidate_sha256", "manifest_schema", "product_tuple_sha256", "qualification_evidence_sha256s", "release_profile", "schema_version"})


@dataclass(frozen=True)
class ManifestInputsV2:
    build: BuildInputIdentityV2
    inventory: ArtifactInventoryV2
    dependencies: DependencyInventoryV1
    product: ProductTupleIdentityV1
    subject: QualificationSubjectIdentityV1
    archive_index: ArchiveIndexV1
    sbom_raw: bytes
    license_report_raw: bytes
    advisory_report_raw: bytes
    checksums_raw: bytes
    evidence_records: tuple[EvidenceRecordV1, ...]
    binding: QualificationBindingV1
    license_policy: tuple[LicensePolicyRecordV1, ...]
    license_exceptions: tuple[dict[str, object], ...]
    notice_artifacts: tuple[dict[str, object], ...]
    advisory_policy: AdvisoryValidationPolicy
    product_components: tuple[ArtifactEntry, ...]
    provenance_sha256: str
    release_notes_sha256: str


@dataclass(frozen=True)
class ReleaseManifestV2:
    inputs: ManifestInputsV2
    evidence: EvidenceSummary
    claims: ClaimMatrixV1
    candidate: ReleaseCandidateIdentityV2
    candidate_sha256: str

    @property
    def inventory(self) -> ArtifactInventoryV2:
        return self.inputs.inventory

    @property
    def product_components(self) -> tuple[ArtifactEntry, ...]:
        return self.inputs.product_components


def assemble_manifest(inputs: ManifestInputsV2) -> ReleaseManifestV2:
    _inputs(inputs)
    if inputs.build.release_profile != "release":
        raise _invalid()
    _evidence_inventory_binding(inputs)
    _advisory(inputs)
    evidence = _evidence(inputs)
    _input(inputs)
    _inventory(inputs)
    _archive(inputs)
    _dependencies(inputs)
    _sbom(inputs)
    _legal(inputs)
    _documents(inputs)
    candidate = _candidate(inputs, evidence)
    claims = current_claim_matrix(inputs.subject.subject_sha256)
    return ReleaseManifestV2(inputs, evidence, claims, candidate, _candidate_digest(candidate))


def parse_manifest(raw: bytes) -> dict[str, object]:
    try:
        document = parse_canonical_json(raw, required=_FIELDS, optional=frozenset())
        if document["schema_version"] != "release-manifest.v2" or document["manifest_schema"] != "release-manifest.v2" or document["release_profile"] != "release":
            raise _invalid()
        for key in _FIELDS - {"schema_version", "manifest_schema", "release_profile", "qualification_evidence_sha256s"}:
            validate_sha256(document[key])
        evidence = document["qualification_evidence_sha256s"]
        if type(evidence) is not list or not evidence or any(type(digest) is not str for digest in evidence):
            raise _invalid()
        for digest in evidence:
            validate_sha256(digest)
        evidence_tuple = tuple(evidence)
        if evidence_tuple != tuple(sorted(set(evidence_tuple))):
            raise _invalid()
        candidate = ReleaseCandidateIdentityV2(document["build_input_sha256"], document["artifact_inventory_sha256"], document["manifest_schema"], document["release_profile"], document["product_tuple_sha256"], evidence_tuple)
        if document["candidate_sha256"] != _candidate_digest(candidate):
            raise _invalid()
        return document
    except ReleaseFailure as error:
        if error.code is FailureCodeV1.MANIFEST_INVALID:
            raise
        raise _invalid() from error


def manifest_bytes(manifest: ReleaseManifestV2) -> bytes:
    _manifest(manifest)
    return canonical_json(_manifest_value(manifest))


def manifest_checks(manifest: object) -> tuple[object, ...]:
    return (lambda: _manifest_type(manifest), lambda: _evidence_inventory_binding(manifest.inputs), lambda: _input(manifest.inputs), lambda: _inventory(manifest.inputs), lambda: _archive(manifest.inputs), lambda: _dependencies(manifest.inputs), lambda: _sbom(manifest.inputs), lambda: _legal(manifest.inputs), lambda: _advisory(manifest.inputs), lambda: _evidence_matches(manifest), lambda: _claims(manifest), lambda: _documents(manifest.inputs), lambda: _candidate_matches(manifest))


def _manifest_type(value: object) -> object:
    if type(value) is not ReleaseManifestV2:
        raise _invalid()
    return None


def _manifest(value: object) -> None:
    _manifest_type(value)
    _inputs(value.inputs)
    _candidate_matches(value)
    _claims(value)


def _inputs(value: object) -> None:
    if type(value) is not ManifestInputsV2 or type(value.build) is not BuildInputIdentityV2 or type(value.inventory) is not ArtifactInventoryV2 or type(value.dependencies) is not DependencyInventoryV1 or type(value.product) is not ProductTupleIdentityV1 or type(value.subject) is not QualificationSubjectIdentityV1 or type(value.archive_index) is not ArchiveIndexV1 or not all(type(raw) is bytes for raw in (value.sbom_raw, value.license_report_raw, value.advisory_report_raw, value.checksums_raw)) or type(value.evidence_records) is not tuple or not all(type(item) is EvidenceRecordV1 for item in value.evidence_records) or type(value.binding) is not QualificationBindingV1 or type(value.license_policy) is not tuple or not all(type(item) is LicensePolicyRecordV1 for item in value.license_policy) or type(value.license_exceptions) is not tuple or not all(type(item) is dict for item in value.license_exceptions) or type(value.notice_artifacts) is not tuple or not all(type(item) is dict for item in value.notice_artifacts) or type(value.advisory_policy) is not AdvisoryValidationPolicy or type(value.product_components) is not tuple or not all(type(item) is ArtifactEntry for item in value.product_components):
        raise _invalid()


def _input(value: ManifestInputsV2) -> None:
    build_sha = _digest(asdict(value.build))
    product_sha = _product_digest(value.product)
    subject_sha = _digest({"build_input_sha256": build_sha, "product_tuple_sha256": product_sha})
    if value.product.build_input_sha256 != build_sha or value.product.artifact_inventory_sha256 != value.inventory.inventory_sha256 or (value.subject.build_input_sha256, value.subject.product_tuple_sha256, value.subject.subject_sha256) != (build_sha, product_sha, subject_sha):
        raise _mismatch()


def _evidence_inventory_binding(value: ManifestInputsV2) -> None:
    if value.binding.artifact_inventory_sha256 != value.inventory.inventory_sha256:
        raise _mismatch()


def _inventory(value: ManifestInputsV2) -> None:
    parse_checksums(value.checksums_raw, value.inventory)
    if value.product_components != value.inventory.entries:
        raise _mismatch()


def _archive(value: ManifestInputsV2) -> None:
    if value.archive_index.candidate_sha256 != value.inventory.candidate_sha256 or value.archive_index.entries != value.inventory.entries:
        raise _mismatch()


def _dependencies(value: ManifestInputsV2) -> None:
    if not value.dependencies.packages or not value.dependencies.inventory_sha256:
        raise ReleaseFailure(FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE, "dependency_inventory_incomplete")


def _sbom(value: ManifestInputsV2) -> None:
    validate_sbom(value.sbom_raw, value.dependencies, value.product, structural_fixture=True)


def _legal(value: ManifestInputsV2) -> None:
    validate_license_report(value.license_report_raw, value.dependencies, value.product, value.license_policy, value.license_exceptions, artifact_inventory=value.inventory, qualification_subject=value.subject, notice_artifacts=value.notice_artifacts, source_date_epoch=value.build.source_date_epoch)


def _advisory(value: ManifestInputsV2) -> None:
    validate_advisory_report(value.advisory_report_raw, value.dependencies, value.product, artifact_inventory=value.inventory, qualification_subject=value.subject, trusted_evaluation_time=value.build.source_date_epoch, structural_fixture=True, validation_policy=value.advisory_policy)


def _evidence(value: ManifestInputsV2) -> EvidenceSummary:
    return validate_evidence(value.evidence_records, value.binding, build_input=value.build, qualification_subject=value.subject, advisory_report_raw=value.advisory_report_raw, structural_fixture=True)


def _documents(value: ManifestInputsV2) -> None:
    for digest in (value.provenance_sha256, value.release_notes_sha256, value.product.provenance_sha256):
        validate_sha256(digest)
    if value.product.provenance_sha256 != value.provenance_sha256:
        raise _mismatch()


def _candidate(value: ManifestInputsV2, evidence: EvidenceSummary) -> ReleaseCandidateIdentityV2:
    _evidence_inventory_binding(value)
    return ReleaseCandidateIdentityV2(_digest(asdict(value.build)), value.inventory.inventory_sha256, "release-manifest.v2", value.build.release_profile, _product_digest(value.product), evidence.evidence_sha256s)


def _candidate_matches(value: ReleaseManifestV2) -> None:
    candidate = _candidate(value.inputs, _evidence(value.inputs))
    if value.candidate != candidate or value.candidate_sha256 != _candidate_digest(candidate):
        raise _mismatch()


def _evidence_matches(value: ReleaseManifestV2) -> None:
    if value.evidence != _evidence(value.inputs):
        raise _mismatch()


def _claims(value: ReleaseManifestV2) -> None:
    if type(value.claims) is not ClaimMatrixV1:
        raise _invalid()
    validate_claim_matrix(value.claims.claims, value.inputs.subject.subject_sha256)


def _manifest_value(value: ReleaseManifestV2) -> dict[str, object]:
    candidate = value.candidate
    return {"artifact_inventory_sha256": candidate.artifact_inventory_sha256, "build_input_sha256": candidate.build_input_sha256, "candidate_sha256": value.candidate_sha256, "manifest_schema": candidate.manifest_schema, "product_tuple_sha256": candidate.product_tuple_sha256, "qualification_evidence_sha256s": list(candidate.qualification_evidence_sha256s), "release_profile": candidate.release_profile, "schema_version": "release-manifest.v2"}


def _product_digest(value: ProductTupleIdentityV1) -> str:
    return _digest(asdict(value))


def _candidate_digest(value: ReleaseCandidateIdentityV2) -> str:
    return _digest(asdict(value))


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _invalid() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "manifest_invalid")


def _mismatch() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.EVIDENCE_CANDIDATE_MISMATCH, "evidence_candidate_mismatch")
