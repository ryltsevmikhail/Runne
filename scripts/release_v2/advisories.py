from dataclasses import dataclass
from enum import Enum

from scripts.release_v2.canonical import parse_canonical_json, validate_sha256
from scripts.release_v2.dependencies_types import DependencyInventoryV1, DependencyPackageV1
from scripts.release_v2.licenses import _validate_artifacts, _validate_inventory, _validate_product, _validate_subject
from scripts.release_v2.model import ArtifactInventoryV2, FailureCodeV1, ProductTupleIdentityV1, QualificationSubjectIdentityV1, ReleaseFailure


class AdvisoryDisposition(str, Enum):
    NOT_AFFECTED = "NOT_AFFECTED"
    REMEDIATED = "REMEDIATED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"
    REPORT_MISSING = "REPORT_MISSING"


_ROOT_FIELDS = frozenset({"candidate_sha256", "database", "findings", "inventory_sha256", "qualification_subject_sha256", "scanner", "schema_version", "source"})
_SOURCE_FIELDS = frozenset({"authenticity_method", "digest", "environment_class", "fresh_until", "produced_at"})
_DATABASE_FIELDS = frozenset({"authority", "digest", "fresh_until", "snapshot_date"})
_SCANNER_FIELDS = frozenset({"name", "tool_sha256", "version"})
_FINDING_FIELDS = frozenset({"advisory_id", "affected_component", "approval_source", "candidate_sha256", "disposition", "expiry", "fixed_version", "inventory_sha256", "owner", "qualification_subject_sha256", "rationale", "reachability", "reachability_evidence", "reviewer", "severity"})
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})


@dataclass(frozen=True)
class AdvisoryValidationPolicy:
    scanner_name: str
    scanner_version: str
    scanner_tool_sha256: str
    database_authority: str
    database_digest: str
    database_snapshot_date: int
    database_fresh_until: int


def validate_advisory_report(raw: bytes, inventory: DependencyInventoryV1, product: ProductTupleIdentityV1, *, artifact_inventory: ArtifactInventoryV2, qualification_subject: QualificationSubjectIdentityV1, trusted_evaluation_time: int, structural_fixture: bool = False, validation_policy: AdvisoryValidationPolicy | None = None) -> None:
    try:
        _validate_inputs(inventory, product, artifact_inventory, qualification_subject, trusted_evaluation_time, structural_fixture, validation_policy)
        if not structural_fixture:
            raise _missing()
        document = parse_canonical_json(raw, required=_ROOT_FIELDS, optional=frozenset())
        _validate_root(document, inventory, artifact_inventory, qualification_subject, trusted_evaluation_time, validation_policy)
        _validate_findings(document["findings"], inventory, artifact_inventory.candidate_sha256, qualification_subject.subject_sha256, trusted_evaluation_time)
    except ReleaseFailure as error:
        if error.code in (FailureCodeV1.ADVISORY_BLOCKED, FailureCodeV1.ADVISORY_REPORT_MISSING):
            raise
        raise _missing() from error
    except Exception as error:
        raise _missing() from error


def _validate_inputs(inventory: object, product: object, artifacts: object, subject: object, now: object, fixture: object, policy: object) -> None:
    if type(now) is not int or now < 0 or type(fixture) is not bool:
        raise _missing()
    _validate_inventory(inventory)
    _validate_product(product)
    _validate_artifacts(artifacts, product)
    _validate_subject(subject, product)
    if fixture:
        _validate_policy(policy, now)
    elif policy is not None:
        _validate_policy(policy, now)


def _validate_root(document: dict[str, object], inventory: DependencyInventoryV1, artifacts: ArtifactInventoryV2, subject: QualificationSubjectIdentityV1, now: int, policy: AdvisoryValidationPolicy | None) -> None:
    if document["schema_version"] != "advisory-report.v1" or document["candidate_sha256"] != artifacts.candidate_sha256 or document["inventory_sha256"] != inventory.inventory_sha256 or document["qualification_subject_sha256"] != subject.subject_sha256:
        raise _missing()
    _sha256(document["candidate_sha256"])
    _sha256(document["inventory_sha256"])
    _sha256(document["qualification_subject_sha256"])
    _validate_source(document["source"], now)
    _validate_database(document["database"], now, policy)
    _validate_scanner(document["scanner"], policy)
    if type(document["findings"]) is not list:
        raise _missing()


def _validate_source(value: object, now: int) -> None:
    if type(value) is not dict or frozenset(value) != _SOURCE_FIELDS:
        raise _missing()
    digest, method, environment, produced, fresh = value["digest"], value["authenticity_method"], value["environment_class"], value["produced_at"], value["fresh_until"]
    _sha256(digest)
    if type(produced) is not int or type(fresh) is not int or produced < 0 or produced > now or fresh <= now:
        raise _missing()
    if method == "STRUCTURAL_FIXTURE" and environment == "FIXTURE":
        return
    raise _missing()


def _validate_database(value: object, now: int, policy: AdvisoryValidationPolicy | None) -> None:
    if type(value) is not dict or frozenset(value) != _DATABASE_FIELDS:
        raise _missing()
    authority, digest, date, fresh = value["authority"], value["digest"], value["snapshot_date"], value["fresh_until"]
    if not _text(authority) or type(date) is not int or type(fresh) is not int or date < 0 or date > now or fresh <= now:
        raise _missing()
    _sha256(digest)
    if policy is not None and (authority != policy.database_authority or digest != policy.database_digest or date != policy.database_snapshot_date or fresh != policy.database_fresh_until):
        raise _missing()


def _validate_scanner(value: object, policy: AdvisoryValidationPolicy | None) -> None:
    if type(value) is not dict or frozenset(value) != _SCANNER_FIELDS or not _text(value["name"]) or not _text(value["version"]):
        raise _missing()
    _sha256(value["tool_sha256"])
    if policy is not None and (value["name"] != policy.scanner_name or value["version"] != policy.scanner_version or value["tool_sha256"] != policy.scanner_tool_sha256):
        raise _missing()


def _validate_policy(value: object, now: int) -> None:
    if type(value) is not AdvisoryValidationPolicy or not _text(value.scanner_name) or not _text(value.scanner_version) or not _text(value.database_authority) or type(value.database_snapshot_date) is not int or type(value.database_fresh_until) is not int or value.database_snapshot_date < 0 or value.database_snapshot_date > now or value.database_fresh_until <= now:
        raise _missing()
    _sha256(value.scanner_tool_sha256)
    _sha256(value.database_digest)


def _validate_findings(values: list[object], inventory: DependencyInventoryV1, candidate: str, subject: str, now: int) -> None:
    identities: set[tuple[bytes, bytes, bytes]] = set()
    previous: tuple[bytes, bytes, bytes] | None = None
    for value in values:
        if type(value) is not dict or frozenset(value) != _FINDING_FIELDS:
            raise _missing()
        package = _package(value["affected_component"], inventory)
        advisory = value["advisory_id"]
        if not _identity(advisory) or not _text(value["severity"]) or value["severity"] not in _SEVERITIES:
            raise _missing()
        identity = (advisory.encode("ascii"), package.reference.encode("ascii"), package.version.encode("ascii"))
        if identity in identities or previous is not None and identity < previous:
            raise _missing()
        identities.add(identity)
        previous = identity
        _validate_finding(value, candidate, subject, inventory.inventory_sha256, now)


def _validate_finding(value: dict[str, object], candidate: str, subject: str, inventory: str, now: int) -> None:
    if value["candidate_sha256"] != candidate or value["qualification_subject_sha256"] != subject or value["inventory_sha256"] != inventory or value["approval_source"] != "IMPORTED_RECORD" or not _text(value["owner"]) or not _prose(value["rationale"]):
        raise _missing()
    _sha256(value["candidate_sha256"])
    _sha256(value["qualification_subject_sha256"])
    _sha256(value["inventory_sha256"])
    reachability, evidence = value["reachability"], value["reachability_evidence"]
    if reachability is None:
        if evidence is not None:
            raise _missing()
    elif reachability not in ("REACHABLE", "NOT_REACHABLE") or not _prose(evidence):
        raise _missing()
    disposition = _disposition(value["disposition"])
    fixed, expiry, reviewer = value["fixed_version"], value["expiry"], value["reviewer"]
    if fixed is not None and not _text(fixed):
        raise _missing()
    if disposition is AdvisoryDisposition.BLOCKED:
        raise _blocked()
    if disposition in (AdvisoryDisposition.UNKNOWN, AdvisoryDisposition.REPORT_MISSING):
        raise _missing()
    if disposition is AdvisoryDisposition.REMEDIATED and fixed is None:
        raise _missing()
    if disposition is AdvisoryDisposition.ACCEPTED_RISK:
        if type(expiry) is not int or expiry <= now or not _text(reviewer) or reviewer == value["owner"]:
            raise _missing()
    elif expiry is not None or reviewer is not None:
        raise _missing()


def _package(value: object, inventory: DependencyInventoryV1) -> DependencyPackageV1:
    if type(value) is not dict:
        raise _missing()
    for package in inventory.packages:
        expected = {"ecosystem": package.ecosystem, "lock_locator": package.lock_locator, "name": package.name, "source_digest": package.source_digest, "version": package.version}
        if value == expected and all(_identity(identity) for identity in expected.values()):
            return package
    raise _missing()


def _disposition(value: object) -> AdvisoryDisposition:
    if type(value) is not str:
        raise _missing()
    try:
        return AdvisoryDisposition(value)
    except ValueError as error:
        raise _missing() from error


def _sha256(value: object) -> None:
    try:
        validate_sha256(value)
    except ReleaseFailure as error:
        raise _missing() from error


def _text(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= 200 and value.isascii() and not any(character.isspace() for character in value) and "://" not in value and "/" not in value and "\\" not in value


def _identity(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= 200 and value.isascii() and all("!" <= character <= "~" for character in value)


def _prose(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= 200 and value.isascii() and value == value.strip() and "  " not in value and not any(character in value for character in ("\n", "\r", "://", "/", "\\"))


def _missing() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.ADVISORY_REPORT_MISSING, "advisory_report_missing")


def _blocked() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.ADVISORY_BLOCKED, "advisory_blocked")
