import hashlib
import json
import unicodedata
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

from scripts.release_v2.canonical import canonical_json, validate_relative_path, validate_sha256
from scripts.release_v2.dependencies_types import DependencyInventoryV1, DependencyPackageV1
from scripts.release_v2.model import ArtifactEntry, ArtifactInventoryV2, FailureCodeV1, ProductTupleIdentityV1, QualificationSubjectIdentityV1, ReleaseFailure


class LicenseDisposition(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNKNOWN = "UNKNOWN"
    EXCEPTION_APPROVED = "EXCEPTION_APPROVED"
    BLOCKED_EVIDENCE = "BLOCKED_EVIDENCE"


class LicenseEvidenceSource(str, Enum):
    COMMITTED_RECORD = "COMMITTED_RECORD"
    IMPORTED_RECORD = "IMPORTED_RECORD"


@dataclass(frozen=True)
class LicensePolicyRecordV1:
    spdx_expression: str
    disposition: LicenseDisposition
    evidence_source: LicenseEvidenceSource
    notice_required: bool
    reviewer: str
    rationale: str
    expiry: int | None


def build_license_report(inventory: DependencyInventoryV1, product: ProductTupleIdentityV1, policy: tuple[LicensePolicyRecordV1, ...], exceptions: tuple[dict[str, object], ...], *, artifact_inventory: ArtifactInventoryV2, notice_artifacts: tuple[dict[str, object], ...], source_date_epoch: int) -> bytes:
    try:
        notices, exception_map = _validate_inputs(inventory, product, policy, exceptions, artifact_inventory, notice_artifacts, source_date_epoch)
        policies = {item.spdx_expression: item for item in policy}
        records = [_package_record(package, policies.get(package.declared_license), exception_map.get(package.reference), notices.get(package.reference)) for package in inventory.packages]
        return canonical_json({"candidate_sha256": artifact_inventory.candidate_sha256, "inventory_sha256": inventory.inventory_sha256, "records": records, "schema_version": "license-report.v1"})
    except ReleaseFailure as error:
        if error.code is FailureCodeV1.LICENSE_EVIDENCE_MISSING:
            raise
        raise _missing() from error
    except Exception as error:
        raise _missing() from error


def bind_license_report(product: ProductTupleIdentityV1, raw: bytes) -> ProductTupleIdentityV1:
    try:
        _validate_product(product)
        if type(raw) is not bytes:
            raise _missing()
        return ProductTupleIdentityV1(product.build_input_sha256, product.artifact_inventory_sha256, product.sbom_sha256, hashlib.sha256(raw).hexdigest(), product.provenance_sha256, product.components, product.schema_revision)
    except ReleaseFailure:
        raise
    except Exception as error:
        raise _missing() from error


def validate_license_report(raw: bytes, inventory: DependencyInventoryV1, product: ProductTupleIdentityV1, policy: tuple[LicensePolicyRecordV1, ...], exceptions: tuple[dict[str, object], ...], *, artifact_inventory: ArtifactInventoryV2, qualification_subject: QualificationSubjectIdentityV1, notice_artifacts: tuple[dict[str, object], ...], source_date_epoch: int) -> None:
    try:
        _validate_subject(qualification_subject, product)
        _validate_inputs(inventory, product, policy, exceptions, artifact_inventory, notice_artifacts, source_date_epoch, qualification_subject)
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != product.license_report_sha256:
            raise _missing()
        document = json.loads(raw.decode("utf-8"))
        expected = build_license_report(inventory, product, policy, exceptions, artifact_inventory=artifact_inventory, notice_artifacts=notice_artifacts, source_date_epoch=source_date_epoch)
        if raw != canonical_json(document) or raw != expected:
            raise _missing()
        dispositions = {record["disposition"] for record in document["records"]}
        if LicenseDisposition.DENIED.value in dispositions:
            raise _denied()
        if dispositions - {LicenseDisposition.ALLOWED.value, LicenseDisposition.EXCEPTION_APPROVED.value}:
            raise _missing()
    except ReleaseFailure as error:
        if error.code in (FailureCodeV1.LICENSE_EVIDENCE_MISSING, FailureCodeV1.LICENSE_DENIED):
            raise
        raise _missing() from error
    except Exception as error:
        raise _missing() from error


def _package_record(package: DependencyPackageV1, policy: LicensePolicyRecordV1 | None, exception: dict[str, object] | None, notice: dict[str, str] | None) -> dict[str, object]:
    if package.declared_license is None:
        return _record(package, LicenseDisposition.UNKNOWN, LicenseEvidenceSource.COMMITTED_RECORD, False, None, "unavailable", "license_evidence_missing", None, None, expression="UNKNOWN")
    if policy is None:
        return _record(package, LicenseDisposition.BLOCKED_EVIDENCE, LicenseEvidenceSource.COMMITTED_RECORD, False, None, "unavailable", "policy_evidence_missing", None, None)
    if policy.disposition is LicenseDisposition.REVIEW_REQUIRED and exception is not None:
        return _record(package, LicenseDisposition.EXCEPTION_APPROVED, LicenseEvidenceSource.IMPORTED_RECORD, policy.notice_required, exception["owner"], exception["reviewer"], exception["rationale"], exception["expiry"], notice)
    return _record(package, policy.disposition, policy.evidence_source, policy.notice_required, None, policy.reviewer, policy.rationale, policy.expiry, notice)


def _validate_inputs(inventory: object, product: object, policy: object, exceptions: object, artifacts: object, notice_artifacts: object, epoch: object, subject: QualificationSubjectIdentityV1 | None = None) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, object]]]:
    _validate_inventory(inventory)
    _validate_product(product)
    _validate_artifacts(artifacts, product)
    if type(epoch) is not int or epoch < 0 or type(policy) is not tuple or type(exceptions) is not tuple:
        raise _missing()
    if not all(type(item) is LicensePolicyRecordV1 for item in policy) or tuple(sorted(policy, key=lambda item: item.spdx_expression.encode("utf-8"))) != policy or len({item.spdx_expression for item in policy}) != len(policy):
        raise _missing()
    for item in policy:
        if not _safe_prose(item.spdx_expression) or type(item.disposition) is not LicenseDisposition or item.disposition is LicenseDisposition.EXCEPTION_APPROVED or type(item.evidence_source) is not LicenseEvidenceSource or type(item.notice_required) is not bool or not _safe_text(item.reviewer) or not _safe_prose(item.rationale) or item.expiry is not None and (type(item.expiry) is not int or item.expiry < 0):
            raise _missing()
    notices = _notice_map(notice_artifacts, inventory, policy, artifacts)
    return notices, _exception_map(exceptions, inventory, policy, artifacts.candidate_sha256, epoch, subject)


def _validate_inventory(inventory: object) -> None:
    if type(inventory) is not DependencyInventoryV1 or type(inventory.packages) is not tuple or not inventory.packages:
        raise _missing()
    packages = inventory.packages
    if not all(type(item) is DependencyPackageV1 and _valid_package(item) for item in packages) or tuple(sorted(packages, key=lambda item: item.reference.encode("utf-8"))) != packages or len({item.reference for item in packages}) != len(packages):
        raise _missing()
    rows = [{"dependencies": list(item.dependencies), "direct": item.direct, "ecosystem": item.ecosystem, "license": item.declared_license, "lock_locator": item.lock_locator, "name": item.name, "source_digest": item.source_digest, "version": item.version} for item in packages]
    if inventory.inventory_sha256 != hashlib.sha256(canonical_json({"schema_version": "dependency-inventory.v1", "packages": rows})).hexdigest():
        raise _missing()


def _validate_artifacts(artifacts: object, product: object) -> None:
    if type(artifacts) is not ArtifactInventoryV2 or artifacts.schema_version != "artifact-inventory-v2" or artifacts.inventory_sha256 != product.artifact_inventory_sha256 or type(artifacts.entries) is not tuple or not artifacts.entries:
        raise _missing()
    rows = []
    for entry in artifacts.entries:
        if type(entry) is not ArtifactEntry or type(entry.path) is not str or validate_relative_path(entry.path) != entry.path or entry.kind not in ("file", "directory") or entry.mode not in ("0644", "0755") or type(entry.size) is not int or entry.size < 0:
            raise _missing()
        validate_sha256(entry.sha256)
        if (entry.kind == "directory" and (entry.mode != "0755" or entry.size != 0 or entry.sha256 != hashlib.sha256(b"").hexdigest())) or (entry.kind == "file" and entry.path == "checksums.sha256"):
            raise _missing()
        rows.append({"kind": entry.kind, "mode": entry.mode, "path": entry.path, "sha256": entry.sha256, "size": entry.size})
    if tuple(sorted(artifacts.entries, key=lambda item: item.path.encode("utf-8"))) != artifacts.entries or len({item.path for item in artifacts.entries}) != len(artifacts.entries):
        raise _missing()
    candidate = hashlib.sha256(canonical_json(rows)).hexdigest()
    digest = hashlib.sha256(canonical_json({"candidate_sha256": candidate, "entries": rows, "schema_version": "artifact-inventory-v2"})).hexdigest()
    if artifacts.candidate_sha256 != candidate or artifacts.inventory_sha256 != digest:
        raise _missing()


def _notice_map(values: object, inventory: DependencyInventoryV1, policy: tuple[LicensePolicyRecordV1, ...], artifacts: ArtifactInventoryV2) -> dict[str, dict[str, str]]:
    if type(values) is not tuple or not all(type(item) is dict for item in values):
        raise _missing()
    policies = {item.spdx_expression: item for item in policy}
    entries = {item.path: item for item in artifacts.entries}
    result: dict[str, dict[str, str]] = {}
    for value in values:
        if set(value) != {"package", "notice"} or type(value["package"]) is not dict or type(value["notice"]) is not dict or set(value["notice"]) != {"path", "sha256"}:
            raise _missing()
        package = next((item for item in inventory.packages if value["package"] == _package(item)), None)
        path, digest = value["notice"].get("path"), value["notice"].get("sha256")
        if package is None or package.reference in result or type(path) is not str or validate_relative_path(path) != path or type(digest) is not str:
            raise _missing()
        entry = entries.get(path)
        if entry is None or entry.kind != "file" or entry.mode != "0644" or entry.sha256 != digest:
            raise _missing()
        result[package.reference] = {"path": path, "sha256": digest}
    expected = {item.reference for item in inventory.packages if (policies.get(item.declared_license) is not None and policies[item.declared_license].notice_required)}
    if set(result) != expected:
        raise _missing()
    return result


def _exception_map(values: tuple[dict[str, object], ...], inventory: DependencyInventoryV1, policy: tuple[LicensePolicyRecordV1, ...], candidate: str, epoch: int, subject: QualificationSubjectIdentityV1 | None) -> dict[str, dict[str, object]]:
    if not all(type(item) is dict for item in values):
        raise _missing()
    policies = {item.spdx_expression: item for item in policy}
    result: dict[str, dict[str, object]] = {}
    required = {"candidate_sha256", "disposition", "evidence_source", "expiry", "license", "owner", "package", "qualification_subject_sha256", "rationale", "reviewer"}
    for item in values:
        package = next((value for value in inventory.packages if item.get("package") == _package(value)), None)
        record = policies.get(package.declared_license) if package is not None else None
        if set(item) != required or type(item["candidate_sha256"]) is not str or type(item["disposition"]) is not str or type(item["evidence_source"]) is not str or type(item["license"]) is not str or type(item["package"]) is not dict or type(item["qualification_subject_sha256"]) is not str or package is None or record is None or package.reference in result or item["candidate_sha256"] != candidate or item["license"] != package.declared_license or item["disposition"] != LicenseDisposition.REVIEW_REQUIRED.value or record.disposition is not LicenseDisposition.REVIEW_REQUIRED or item["evidence_source"] != LicenseEvidenceSource.IMPORTED_RECORD.value or type(item["expiry"]) is not int or item["expiry"] <= epoch or not _safe_text(item["owner"]) or not _safe_text(item["reviewer"]) or not _safe_prose(item["rationale"]) or unicodedata.normalize("NFC", item["owner"]) == unicodedata.normalize("NFC", item["reviewer"]):
            raise _missing()
        try:
            validate_sha256(item["qualification_subject_sha256"])
        except ReleaseFailure as error:
            raise _missing() from error
        if subject is not None and item["qualification_subject_sha256"] != subject.subject_sha256:
            raise _missing()
        result[package.reference] = item
    return result


def _validate_subject(subject: object, product: ProductTupleIdentityV1) -> None:
    if type(subject) is not QualificationSubjectIdentityV1:
        raise _missing()
    tuple_sha256 = hashlib.sha256(canonical_json({"artifact_inventory_sha256": product.artifact_inventory_sha256, "build_input_sha256": product.build_input_sha256, "components": list(product.components), "license_report_sha256": product.license_report_sha256, "provenance_sha256": product.provenance_sha256, "sbom_sha256": product.sbom_sha256, "schema_revision": product.schema_revision})).hexdigest()
    subject_sha256 = hashlib.sha256(canonical_json({"build_input_sha256": product.build_input_sha256, "product_tuple_sha256": tuple_sha256})).hexdigest()
    if subject.build_input_sha256 != product.build_input_sha256 or subject.product_tuple_sha256 != tuple_sha256 or subject.subject_sha256 != subject_sha256:
        raise _missing()


def _valid_package(item: DependencyPackageV1) -> bool:
    return all(_safe_text(value) for value in (item.ecosystem, item.name, item.version, item.source_digest)) and _safe_locator(item.lock_locator) and (item.declared_license is None or _safe_text(item.declared_license)) and type(item.dependencies) is tuple and all(_safe_text(value) for value in item.dependencies) and type(item.direct) is bool


def _validate_product(product: object) -> None:
    if type(product) is not ProductTupleIdentityV1 or type(product.components) is not tuple or not all(type(item) is str for item in product.components) or not _safe_text(product.schema_revision):
        raise _missing()
    try:
        for value in (product.build_input_sha256, product.artifact_inventory_sha256, product.sbom_sha256, product.license_report_sha256, product.provenance_sha256):
            validate_sha256(value)
    except ReleaseFailure as error:
        raise _missing() from error


def _record(package: DependencyPackageV1, disposition: LicenseDisposition, source: LicenseEvidenceSource, notice: bool, owner: object, reviewer: object, rationale: object, expiry: object, artifact: object, *, expression: str | None = None) -> dict[str, object]:
    return {"detected_spdx_expression": package.declared_license if expression is None else expression, "disposition": disposition.value, "evidence_source": source.value, "exception_owner": owner, "expiry": expiry, "notice_artifact": artifact, "notice_required": notice, "package": _package(package), "rationale": rationale, "reviewer": reviewer}


def _package(package: DependencyPackageV1) -> dict[str, str]:
    return {"ecosystem": package.ecosystem, "lock_locator": package.lock_locator, "name": package.name, "source_digest": package.source_digest, "version": package.version}


def _safe_text(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= 200 and value.isascii() and not any(character.isspace() for character in value) and "://" not in value and "/" not in value and "\\" not in value and not any(word in value.lower() for word in ("credential", "password", "secret", "token"))


def _safe_prose(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= 200 and value.isascii() and value == value.strip() and "  " not in value and not any(character in value for character in ("\n", "\r", "://", "/", "\\")) and not any(word in value.lower() for word in ("credential", "password", "secret", "token"))


def _safe_locator(value: object) -> bool:
    if type(value) is not str or not value or not value.isascii() or any(character.isspace() for character in value) or "?" in value or "#" in value:
        return False
    if "://" not in value:
        return True
    parsed = urlsplit(value)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc) and parsed.username is None and parsed.password is None and "@" not in parsed.netloc


def _missing() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.LICENSE_EVIDENCE_MISSING, "license_evidence_missing")


def _denied() -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.LICENSE_DENIED, "license_denied")
