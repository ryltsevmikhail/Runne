from dataclasses import dataclass
from pathlib import Path

from scripts.release_v2.archive import verify_archive_bytes, verify_archive_index
from scripts.release_v2.claims import fixture_gate_result, production_gate_result
from scripts.release_v2.inventory import TreeBytes, capture_tree_bytes, parse_checksums, verify_checksums
from scripts.release_v2.manifest import ReleaseManifestV2, manifest_bytes, manifest_checks, parse_manifest
from scripts.release_v2.model import BuildInputIdentityV2, ClaimDisposition, FailureCodeV1, FailureRecordV1, GateResultV1, OverallStatus, ProductionGateV1, ReleaseFailure
from scripts.release_v2.preflight import preflight_candidate
from scripts.release_v2.repository_snapshot import RepositorySnapshot, capture_repository


@dataclass(frozen=True)
class GateVerificationContext:
    source_root: Path | None
    candidate_root: Path | None
    archive_path: Path | None
    archive_index_path: Path | None
    manifest_raw: bytes
    advisory_report_raw: bytes
    checksums_raw: bytes
    fixture_tree: TreeBytes | None = None
    archive_raw: bytes | None = None
    archive_index_raw: bytes | None = None


def evaluate_gate(manifest: ReleaseManifestV2, *, context: GateVerificationContext, fixture_mode: bool) -> GateResultV1:
    if type(fixture_mode) is not bool:
        return _blocked((ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "fixture_mode_invalid"),))
    try:
        checks = manifest_checks(manifest)
    except ReleaseFailure as error:
        return _blocked((error,))
    failures: list[ReleaseFailure] = []
    for check in checks:
        try:
            check()
        except ReleaseFailure as error:
            failures.append(error)
        except Exception:
            failures.append(ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "gate_record_invalid"))
    if failures:
        return _blocked(tuple(failures))
    try:
        _verify_context(manifest, context)
    except ReleaseFailure as error:
        return _blocked((error,))
    except Exception:
        return _blocked((ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "gate_context_invalid"),))
    return fixture_gate_result(manifest.claims) if fixture_mode else production_gate_result(manifest.claims)


def production_gate_exit_code(result: GateResultV1) -> int:
    if type(result) is not GateResultV1 or result.production_approved:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "gate_result_invalid")
    return 1


def _blocked(errors: tuple[ReleaseFailure, ...]) -> GateResultV1:
    records = tuple(sorted({(error.code, error.detail) for error in errors}, key=lambda item: (item[0].value, item[1])))
    failures = tuple(FailureRecordV1(code, detail) for code, detail in records)
    return GateResultV1("release-v2-result.v1", OverallStatus.BLOCKED_EVIDENCE, False, ProductionGateV1(ClaimDisposition.BLOCKED, FailureCodeV1.PRODUCTION_GATE_BLOCKED), failures, ())


def _verify_context(manifest: ReleaseManifestV2, context: GateVerificationContext) -> None:
    if type(context) is not GateVerificationContext or not all(type(value) is bytes for value in (context.manifest_raw, context.advisory_report_raw, context.checksums_raw)):
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "gate_context_invalid")
    if context.fixture_tree is not None:
        _verify_fixture_context(manifest, context)
        return
    if not all(isinstance(value, Path) for value in (context.source_root, context.candidate_root, context.archive_path, context.archive_index_path)):
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "gate_context_invalid")
    source_before: RepositorySnapshot | None = None
    candidate_before: TreeBytes | None = None
    try:
        source_before, candidate_before = capture_repository(context.source_root), capture_tree_bytes(context.candidate_root)
        parsed = parse_manifest(context.manifest_raw)
        if context.manifest_raw != manifest_bytes(manifest) or context.advisory_report_raw != manifest.inputs.advisory_report_raw or context.checksums_raw != manifest.inputs.checksums_raw:
            raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "gate_raw_input_mismatch")
        if parsed["candidate_sha256"] != manifest.candidate_sha256:
            raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "gate_candidate_mismatch")
        _preflight_source_only(context.source_root, manifest.inputs.build)
        verify_checksums(context.candidate_root, context.checksums_raw, manifest.inventory)
        archive = verify_archive_index(context.archive_path, context.archive_index_path, manifest.inventory.candidate_sha256, manifest.inputs.build.source_date_epoch)
        if archive != manifest.inputs.archive_index:
            raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "archive_index_mismatch")
    finally:
        _verify_inputs_unchanged(source_before, candidate_before, context)


def _verify_fixture_context(manifest: ReleaseManifestV2, context: GateVerificationContext) -> None:
    if type(context.fixture_tree) is not TreeBytes or type(context.archive_raw) is not bytes or type(context.archive_index_raw) is not bytes:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "fixture_gate_context_invalid")
    parsed = parse_manifest(context.manifest_raw)
    if context.manifest_raw != manifest_bytes(manifest) or parsed["candidate_sha256"] != manifest.candidate_sha256 or context.advisory_report_raw != manifest.inputs.advisory_report_raw or context.checksums_raw != manifest.inputs.checksums_raw:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "gate_raw_input_mismatch")
    tree = context.fixture_tree
    if tree.candidate_sha256 != manifest.inventory.candidate_sha256 or tree.entries != manifest.inventory.entries:
        raise ReleaseFailure(FailureCodeV1.CHECKSUM_INVALID, "fixture_candidate_mismatch")
    parse_checksums(context.checksums_raw, manifest.inventory)
    archive = verify_archive_bytes(context.archive_raw, context.archive_index_raw, manifest.inventory.candidate_sha256, manifest.inputs.build.source_date_epoch)
    if archive != manifest.inputs.archive_index:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "archive_index_mismatch")


def _preflight_source_only(source_root: Path, build: BuildInputIdentityV2) -> None:
    """Verify the Git source twice; staging bytes use the inventory checks below."""
    preflight_candidate(source_root, source_root, build)


def _verify_inputs_unchanged(source_before: RepositorySnapshot | None, candidate_before: TreeBytes | None, context: GateVerificationContext) -> None:
    try:
        source_after, candidate_after = capture_repository(context.source_root), capture_tree_bytes(context.candidate_root)
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.INPUT_MUTATION_DETECTED, "input_final_capture_failed") from error
    if source_before is None or candidate_before is None:
        return
    if (source_before, candidate_before) != (source_after, candidate_after):
        raise ReleaseFailure(FailureCodeV1.INPUT_MUTATION_DETECTED, "input_snapshot_changed")
