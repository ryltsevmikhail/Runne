"""Closed byte-only reconstruction for the deterministic structural fixture."""

from dataclasses import dataclass
from pathlib import Path

from scripts.release_v2.advisories import AdvisoryValidationPolicy
from scripts.release_v2.archive import ArchiveIndexV1, archive_tree_bytes
from scripts.release_v2.canonical import parse_canonical_json
from scripts.release_v2.claims import ClaimMatrixV1, current_claim_matrix
from scripts.release_v2.dependencies_types import DependencyInventoryV1, DependencyPackageV1
from scripts.release_v2.evidence import EvidenceCheckV1, EvidenceRecordV1, QualificationBindingV1, ReviewBindingV1
from scripts.release_v2.fixture_metadata_contract import parse_fixture_metadata
from scripts.release_v2.gate import GateVerificationContext
from scripts.release_v2.inventory import TreeBytes, parse_inventory
from scripts.release_v2.licenses import LicenseDisposition, LicenseEvidenceSource, LicensePolicyRecordV1
from scripts.release_v2.manifest import ManifestInputsV2, ReleaseManifestV2, assemble_manifest, manifest_bytes
from scripts.release_v2.model import ArtifactEntry, BuildInputIdentityV2, ClaimDisposition, ClaimRecordV1, FailureCodeV1, ProductTupleIdentityV1, QualificationSubjectIdentityV1, ReleaseFailure


_AUXILIARY_FIELDS = frozenset(("advisory_policy", "binding", "license_exceptions", "license_policy", "notice_artifacts", "provenance_sha256", "release_notes_sha256", "schema_version"))
_BUILD_FIELDS = frozenset(("cargo_lock_sha256", "platform", "pnpm_lock_sha256", "profile_digests", "release_profile", "release_version", "schema_version", "source_date_epoch", "source_revision", "source_tree_sha256", "target", "toolchain"))
_PRODUCT_FIELDS = frozenset(("artifact_inventory_sha256", "build_input_sha256", "components", "license_report_sha256", "provenance_sha256", "sbom_sha256", "schema_revision"))
_SUBJECT_FIELDS = frozenset(("build_input_sha256", "product_tuple_sha256", "subject_sha256"))


@dataclass(frozen=True)
class LoadedFixtureGate:
    manifest: ReleaseManifestV2
    context: GateVerificationContext


@dataclass(frozen=True)
class ValidatedFixtureIdentity:
    candidate_sha256: str
    qualification_subject_sha256: str


def load_fixture_gate(tree: TreeBytes) -> LoadedFixtureGate:
    """Reconstruct all Task11 gate inputs from one immutable fixture snapshot."""
    if type(tree) is not TreeBytes:
        raise _invalid()
    try:
        raw = {name: tree.bytes_for(name) for name in _required_files()}
        auxiliary = parse_canonical_json(raw["fixture-inputs.v1.json"], required=_AUXILIARY_FIELDS, optional=frozenset())
        if auxiliary["schema_version"] != "release-fixture-inputs.v1":
            raise ValueError
        build = _build(raw["build-input.v2.json"])
        inventory = parse_inventory(raw["artifact-inventory.v2.json"])
        dependencies = _dependencies(raw["dependency-inventory.v1.json"])
        product = _product(raw["product-tuple.v1.json"])
        subject = _subject(raw["qualification-subject.v1.json"])
        archive = _archive(raw["archive-index.v1.json"])
        records = _evidence(raw["qualification-evidence.v1.json"])
        inputs = ManifestInputsV2(build, inventory, dependencies, product, subject, archive, raw["sbom.cdx.json"], raw["license-report.v1.json"], raw["advisory-report.v1.json"], raw["checksums.sha256"], records, _binding(auxiliary["binding"]), _policy(auxiliary["license_policy"]), _dicts(auxiliary["license_exceptions"]), _dicts(auxiliary["notice_artifacts"]), _advisory_policy(auxiliary["advisory_policy"]), inventory.entries, auxiliary["provenance_sha256"], auxiliary["release_notes_sha256"])
        manifest = assemble_manifest(inputs)
        if manifest_bytes(manifest) != raw["manifest.v2.json"] or _claims(raw["claim-matrix.v1.json"], subject) != manifest.claims:
            raise _invalid()
        parse_fixture_metadata(
            {name: raw[name] for name in ("fixture-result.v1.json", "provenance.v1.json", "release-snapshot.v1.json")},
            build,
            inventory,
            manifest.claims,
            manifest.candidate_sha256,
            manifest.evidence.evidence_sha256s,
            archive,
        )
        candidate_tree = archive_tree_bytes(raw["archive.tar"], raw["archive-index.v1.json"], inventory.candidate_sha256, build.source_date_epoch)
        context = GateVerificationContext(None, None, None, None, raw["manifest.v2.json"], raw["advisory-report.v1.json"], raw["checksums.sha256"], candidate_tree, raw["archive.tar"], raw["archive-index.v1.json"])
        return LoadedFixtureGate(manifest, context)
    except ReleaseFailure:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise _invalid() from error


def load_validated_fixture_identity(tree: TreeBytes) -> ValidatedFixtureIdentity:
    loaded = load_fixture_gate(tree)
    return ValidatedFixtureIdentity(loaded.manifest.candidate_sha256, loaded.manifest.inputs.subject.subject_sha256)


def _required_files() -> tuple[str, ...]:
    return ("advisory-report.v1.json", "archive-index.v1.json", "archive.tar", "artifact-inventory.v2.json", "build-input.v2.json", "checksums.sha256", "claim-matrix.v1.json", "dependency-inventory.v1.json", "fixture-inputs.v1.json", "fixture-result.v1.json", "license-report.v1.json", "manifest.v2.json", "product-tuple.v1.json", "provenance.v1.json", "qualification-evidence.v1.json", "qualification-subject.v1.json", "release-snapshot.v1.json", "sbom.cdx.json")


def _build(raw: bytes) -> BuildInputIdentityV2:
    value = parse_canonical_json(raw, required=_BUILD_FIELDS, optional=frozenset())
    return BuildInputIdentityV2(value["schema_version"], value["source_revision"], value["source_tree_sha256"], value["release_version"], value["target"], value["platform"], _strings(value["profile_digests"]), value["toolchain"], value["cargo_lock_sha256"], value["pnpm_lock_sha256"], value["release_profile"], value["source_date_epoch"])


def _dependencies(raw: bytes) -> DependencyInventoryV1:
    value = parse_canonical_json(raw, required=frozenset(("inventory_sha256", "packages")), optional=frozenset())
    if type(value["packages"]) is not list:
        raise ValueError
    packages = tuple(DependencyPackageV1(row["ecosystem"], row["name"], row["version"], row["lock_locator"], row["source_digest"], row["declared_license"], _strings(row["dependencies"]), row["direct"]) for row in value["packages"] if type(row) is dict and frozenset(row) == frozenset(("declared_license", "dependencies", "direct", "ecosystem", "lock_locator", "name", "source_digest", "version")))
    if len(packages) != len(value["packages"]):
        raise ValueError
    return DependencyInventoryV1(packages, value["inventory_sha256"])


def _product(raw: bytes) -> ProductTupleIdentityV1:
    value = parse_canonical_json(raw, required=_PRODUCT_FIELDS, optional=frozenset())
    return ProductTupleIdentityV1(value["build_input_sha256"], value["artifact_inventory_sha256"], value["sbom_sha256"], value["license_report_sha256"], value["provenance_sha256"], _strings(value["components"]), value["schema_revision"])


def _subject(raw: bytes) -> QualificationSubjectIdentityV1:
    value = parse_canonical_json(raw, required=_SUBJECT_FIELDS, optional=frozenset())
    return QualificationSubjectIdentityV1(value["build_input_sha256"], value["product_tuple_sha256"], value["subject_sha256"])


def _archive(raw: bytes) -> ArchiveIndexV1:
    value = parse_canonical_json(raw, required=frozenset(("archive_sha256", "candidate_sha256", "entries", "format", "schema_version", "size")), optional=frozenset())
    if type(value["entries"]) is not list:
        raise ValueError
    return ArchiveIndexV1(value["schema_version"], value["archive_sha256"], value["format"], value["size"], value["candidate_sha256"], tuple(_entry(row) for row in value["entries"]))


def _evidence(raw: bytes) -> tuple[EvidenceRecordV1, ...]:
    value = parse_canonical_json(raw, required=frozenset(("records", "schema_version")), optional=frozenset())
    if value["schema_version"] != "release-evidence.v1" or type(value["records"]) is not list:
        raise ValueError
    return tuple(_record(row) for row in value["records"])


def _record(row: object) -> EvidenceRecordV1:
    if type(row) is not dict or frozenset(row) != frozenset(EvidenceRecordV1.__dataclass_fields__):
        raise ValueError
    checks, review = row["checks"], row["review"]
    if type(checks) is not list or type(review) is not dict or frozenset(review) != frozenset(ReviewBindingV1.__dataclass_fields__):
        raise ValueError
    parsed_checks = tuple(EvidenceCheckV1(item["name"], item["digest"], item["result"]) for item in checks if type(item) is dict and frozenset(item) == frozenset(EvidenceCheckV1.__dataclass_fields__))
    if len(parsed_checks) != len(checks):
        raise ValueError
    return EvidenceRecordV1(*[row[field] if field not in ("checks", "review") else parsed_checks if field == "checks" else ReviewBindingV1(**review) for field in EvidenceRecordV1.__dataclass_fields__])


def _binding(value: object) -> QualificationBindingV1:
    if type(value) is not dict or frozenset(value) != frozenset(QualificationBindingV1.__dataclass_fields__):
        raise ValueError
    return QualificationBindingV1(**value)


def _policy(value: object) -> tuple[LicensePolicyRecordV1, ...]:
    if type(value) is not list:
        raise ValueError
    records = tuple(_policy_record(item) for item in value)
    if len(records) != len(value):
        raise ValueError
    return records


def _policy_record(value: object) -> LicensePolicyRecordV1:
    if type(value) is not dict or frozenset(value) != frozenset(LicensePolicyRecordV1.__dataclass_fields__):
        raise ValueError
    return LicensePolicyRecordV1(value["spdx_expression"], LicenseDisposition(value["disposition"]), LicenseEvidenceSource(value["evidence_source"]), value["notice_required"], value["reviewer"], value["rationale"], value["expiry"])


def _advisory_policy(value: object) -> AdvisoryValidationPolicy:
    if type(value) is not dict or frozenset(value) != frozenset(AdvisoryValidationPolicy.__dataclass_fields__):
        raise ValueError
    return AdvisoryValidationPolicy(**value)


def _claims(raw: bytes, subject: QualificationSubjectIdentityV1) -> ClaimMatrixV1:
    value = parse_canonical_json(raw, required=frozenset(("claims", "schema_version", "subject_sha256")), optional=frozenset())
    if value["schema_version"] != "release-claim-matrix.v1" or value["subject_sha256"] != subject.subject_sha256 or type(value["claims"]) is not list:
        raise ValueError
    claims = tuple(ClaimRecordV1(item["claim_id"], ClaimDisposition(item["disposition"]), None if item["blocker_code"] is None else FailureCodeV1(item["blocker_code"]), item["subject_sha256"]) for item in value["claims"] if type(item) is dict and frozenset(item) == frozenset(("blocker_code", "claim_id", "disposition", "subject_sha256")))
    if len(claims) != len(value["claims"]):
        raise ValueError
    return ClaimMatrixV1(subject.subject_sha256, claims)


def _entry(value: object) -> ArtifactEntry:
    if type(value) is not dict or frozenset(value) != frozenset(ArtifactEntry.__dataclass_fields__):
        raise ValueError
    return ArtifactEntry(**value)


def _strings(value: object) -> tuple[str, ...]:
    if type(value) is not list or not all(type(item) is str for item in value):
        raise ValueError
    return tuple(value)


def _dicts(value: object) -> tuple[dict[str, object], ...]:
    if type(value) is not list or value:
        raise ValueError
    return ()


def _invalid() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "fixture_loader_invalid")
