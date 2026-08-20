"""Deterministic inert structural fixture generator; never a product packager."""

import hashlib
import tempfile
from dataclasses import asdict, replace
from pathlib import Path

from scripts.release_v2.advisories import AdvisoryValidationPolicy
from scripts.release_v2.archive import build_archive
from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.claims import current_claim_matrix
from scripts.release_v2.dependencies_types import DependencyInventoryV1, DependencyPackageV1
from scripts.release_v2.evidence import (
    EvidenceCheckV1, EvidenceRecordV1, HostedLaneV1, QualificationBindingV1,
    ReviewBindingV1, evidence_digest_payload, payload_digest_payload,
    qualification_binding_digest, validate_evidence,
)
from scripts.release_v2.fixture_metadata_contract import (
    render_fixture_metadata,
    render_provenance,
)
from scripts.release_v2.human_fixture_contract import canonical_human_artifacts
from scripts.release_v2.inventory import build_inventory, checksum_rows
from scripts.release_v2.licenses import (
    LicenseDisposition, LicenseEvidenceSource, LicensePolicyRecordV1,
    bind_license_report, build_license_report,
)
from scripts.release_v2.manifest import ManifestInputsV2, assemble_manifest, manifest_bytes
from scripts.release_v2.model import (
    ArtifactEntry, BuildInputIdentityV2, ProductTupleIdentityV1,
    QualificationSubjectIdentityV1,
)
from scripts.release_v2.sbom import bind_sbom, build_sbom


SOURCE_DATE_EPOCH = 1_700_000_000
FIXTURE_SOURCE_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_COMPONENTS = {
    "Desktop.bundle": (b"", 0o755),
    "Desktop.bundle/desktop.inert": (b"desktop structural fixture\n", 0o755),
    "Desktop.bundle/runned.inert": (b"bundled runtime structural fixture\n", 0o755),
    "LEGAL.txt": (b"fixture legal notice\n", 0o644),
}


def generate_fixture(output_root: Path) -> tuple[Path, ...]:
    """Write a complete inert fixture only into an absent or empty directory."""
    if output_root.exists() and (not output_root.is_dir() or any(output_root.iterdir())):
        raise ValueError("fixture output must be absent or empty")
    output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        candidate = root / "candidate"
        _write_components(candidate)
        values = _fixture_values(candidate, root / "archive")
    for name, raw in values.items():
        target = output_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.parent.chmod(0o755)
        target.chmod(0o644)
    for name, raw in tuple(values.items()):
        target = output_root / f"{name}.sha256"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"{_digest(raw)}  {name}\n", encoding="utf-8")
        target.parent.chmod(0o755)
        target.chmod(0o644)
    return tuple(sorted(path.relative_to(output_root) for path in output_root.rglob("*") if path.is_file()))


def _fixture_values(candidate: Path, archive_root: Path) -> dict[str, bytes]:
    inventory = _inventory(candidate)
    build = BuildInputIdentityV2("build-input-v2", FIXTURE_SOURCE_SHA, "b" * 64, "0.0.0-fixture", "x86_64-unknown-linux-gnu", "linux", ("c" * 64,), "rust-1.97.1", "d" * 64, "e" * 64, "release", SOURCE_DATE_EPOCH)
    build_raw, provenance = canonical_json(asdict(build)), render_provenance(build, inventory)
    product = ProductTupleIdentityV1(_digest(build_raw), inventory.inventory_sha256, "0" * 64, "0" * 64, _digest(provenance), ("DesktopBundle", "bundledDaemon", "legal", "sbom"), "product-tuple-v1")
    dependencies = _dependencies()
    sbom = build_sbom(dependencies, product, structural_fixture=True)
    product = bind_sbom(product, sbom)
    policy = (LicensePolicyRecordV1("MIT", LicenseDisposition.ALLOWED, LicenseEvidenceSource.COMMITTED_RECORD, False, "fixture_reviewer", "fixture_policy", None),)
    license_raw = build_license_report(dependencies, product, policy, (), artifact_inventory=inventory, notice_artifacts=(), source_date_epoch=SOURCE_DATE_EPOCH)
    product = bind_license_report(product, license_raw)
    product_raw = canonical_json(asdict(product))
    subject = _subject(product)
    advisory, advisory_policy = _advisory(inventory, dependencies, subject)
    binding = QualificationBindingV1(subject.subject_sha256, build.source_tree_sha256, subject.product_tuple_sha256, inventory.inventory_sha256, _digest(advisory), "release")
    evidence = _evidence(build, subject, binding, advisory)
    archive_root.mkdir()
    archive_index = build_archive(candidate, archive_root, SOURCE_DATE_EPOCH, inventory.candidate_sha256)
    inputs = ManifestInputsV2(build, inventory, dependencies, product, subject, archive_index, sbom, license_raw, advisory, checksum_rows(inventory), evidence.records, binding, policy, (), (), advisory_policy, inventory.entries, _digest(provenance), _digest(canonical_json({"kind": "fixture_release_notes"})))
    manifest = assemble_manifest(inputs)
    claims = current_claim_matrix(subject.subject_sha256)
    claim_raw = canonical_json({"claims": [_claim(value) for value in claims.claims], "schema_version": "release-claim-matrix.v1", "subject_sha256": subject.subject_sha256})
    evidence_raw = canonical_json({"records": [asdict(value) for value in evidence.records], "schema_version": "release-evidence.v1"})
    metadata = render_fixture_metadata(build, inventory, claims, manifest.candidate_sha256, evidence.evidence_sha256s, archive_index)
    values = {
        "advisory-report.v1.json": advisory,
        "archive-index.v1.json": canonical_json(archive_index.as_dict()),
        "archive.tar": (archive_root / "archive.tar").read_bytes(),
        "artifact-inventory.v2.json": canonical_json(asdict(inventory)),
        "build-input.v2.json": build_raw,
        "checksums.sha256": checksum_rows(inventory),
        "claim-matrix.v1.json": claim_raw,
        "dependency-inventory.v1.json": canonical_json(asdict(dependencies)),
        "fixture-result.v1.json": metadata["fixture-result.v1.json"],
        "fixture-inputs.v1.json": _fixture_inputs(binding, policy, advisory_policy, _digest(provenance), _digest(canonical_json({"kind": "fixture_release_notes"}))),
        "license-report.v1.json": license_raw,
        "manifest.v2.json": manifest_bytes(manifest),
        "product-tuple.v1.json": product_raw,
        "provenance.v1.json": metadata["provenance.v1.json"],
        "qualification-evidence.v1.json": evidence_raw,
        "qualification-subject.v1.json": canonical_json(asdict(subject)),
        "release-snapshot.v1.json": metadata["release-snapshot.v1.json"],
        "sbom.cdx.json": sbom,
    }
    values.update(canonical_human_artifacts(manifest.candidate_sha256, build.release_version, build.source_tree_sha256))
    return values


def _write_components(root: Path) -> None:
    for name, (raw, mode) in _COMPONENTS.items():
        target = root / name
        if raw:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        else:
            target.mkdir(parents=True, exist_ok=True)
        target.chmod(mode)


def _fixture_inputs(binding, policy, advisory_policy, provenance_sha256: str, release_notes_sha256: str) -> bytes:
    return canonical_json({
        "advisory_policy": asdict(advisory_policy),
        "binding": asdict(binding),
        "license_exceptions": [],
        "license_policy": [{"disposition": item.disposition.value, "evidence_source": item.evidence_source.value, "expiry": item.expiry, "notice_required": item.notice_required, "rationale": item.rationale, "reviewer": item.reviewer, "spdx_expression": item.spdx_expression} for item in policy],
        "notice_artifacts": [],
        "provenance_sha256": provenance_sha256,
        "release_notes_sha256": release_notes_sha256,
        "schema_version": "release-fixture-inputs.v1",
    })


def _inventory(root: Path):
    entries = tuple(ArtifactEntry(name, "directory" if not raw else "file", "0755" if mode == 0o755 else "0644", len(raw), _digest(raw)) for name, (raw, mode) in _COMPONENTS.items())
    return build_inventory(root, entries)


def _dependencies() -> DependencyInventoryV1:
    package = DependencyPackageV1("bundled", "bundled-daemon", "0.0.0-fixture", "artifact:bundled-daemon", _digest(_COMPONENTS["Desktop.bundle/runned.inert"][0]), "MIT", (), True)
    rows = [{"dependencies": [], "direct": True, "ecosystem": package.ecosystem, "license": package.declared_license, "lock_locator": package.lock_locator, "name": package.name, "source_digest": package.source_digest, "version": package.version}]
    return DependencyInventoryV1((package,), _digest(canonical_json({"packages": rows, "schema_version": "dependency-inventory.v1"})))


def _subject(product: ProductTupleIdentityV1) -> QualificationSubjectIdentityV1:
    product_sha = _digest(canonical_json(asdict(product)))
    return QualificationSubjectIdentityV1(product.build_input_sha256, product_sha, _digest(canonical_json({"build_input_sha256": product.build_input_sha256, "product_tuple_sha256": product_sha})))


def _advisory(inventory, dependencies, subject):
    policy = AdvisoryValidationPolicy("fixture_scanner", "1", "f" * 64, "fixture_db", "e" * 64, SOURCE_DATE_EPOCH - 1, SOURCE_DATE_EPOCH + 1)
    raw = canonical_json({"candidate_sha256": inventory.candidate_sha256, "database": {"authority": policy.database_authority, "digest": policy.database_digest, "fresh_until": policy.database_fresh_until, "snapshot_date": policy.database_snapshot_date}, "findings": [], "inventory_sha256": dependencies.inventory_sha256, "qualification_subject_sha256": subject.subject_sha256, "scanner": {"name": policy.scanner_name, "tool_sha256": policy.scanner_tool_sha256, "version": policy.scanner_version}, "schema_version": "advisory-report.v1", "source": {"authenticity_method": "STRUCTURAL_FIXTURE", "digest": "d" * 64, "environment_class": "FIXTURE", "fresh_until": SOURCE_DATE_EPOCH + 1, "produced_at": SOURCE_DATE_EPOCH - 1}})
    return raw, policy


def _evidence(build, subject, binding, advisory):
    records = []
    for lane, platform, target, tool in HostedLaneV1.required_slots():
        names = ("artifact_digest", "build", "clippy", "docs", "rustdoc", "tests") + (("advisory_report",) if lane == "linux-pinned" else ())
        checks = tuple(EvidenceCheckV1(name, _digest(advisory) if name == "advisory_report" else _digest(name.encode()), "PASS") for name in names)
        record = EvidenceRecordV1("hosted-qualification", "qualification-evidence.v1", subject.subject_sha256, qualification_binding_digest(binding), _digest(canonical_json(payload_digest_payload(checks))), "structural_fixture", SOURCE_DATE_EPOCH - 1, SOURCE_DATE_EPOCH + 1, "STRUCTURAL_FIXTURE", "FIXTURE", "PASS", binding.source_sha256, binding.product_tuple_sha256, binding.artifact_inventory_sha256, platform, target, binding.profile, tool, "ACTUAL", lane, "1" * 64, "2" * 64, "3" * 64, checks, ReviewBindingV1("fixture_owner", "release_owner", "fixture_reviewer", "independent_reviewer", f"review_{lane}"), "")
        records.append(replace(record, evidence_sha256=_digest(canonical_json(evidence_digest_payload(record)))))
    return validate_evidence(tuple(records), binding, build_input=build, qualification_subject=subject, advisory_report_raw=advisory, structural_fixture=True)


def _claim(value) -> dict[str, object]:
    return {"blocker_code": None if value.blocker_code is None else value.blocker_code.value, "claim_id": value.claim_id, "disposition": value.disposition.value, "subject_sha256": value.subject_sha256}


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
