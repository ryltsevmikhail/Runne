import re
from dataclasses import dataclass
from pathlib import Path

from scripts.release_v2.canonical import sort_utf8, validate_sha256
from scripts.release_v2.model import BuildInputIdentityV2, FailureCodeV1, ReleaseFailure
from scripts.release_v2.repository_snapshot import capture_repository


_REVISION = re.compile(r"[0-9a-f]{40}")
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")
_TARGETS = frozenset(("x86_64-unknown-linux-gnu",))
_PLATFORMS = frozenset(("linux",))
_TOOLCHAINS = frozenset(("rust-1.97.1",))
_RELEASE_PROFILES = frozenset(("release",))


@dataclass(frozen=True)
class BuildRequest:
    release_version: str
    target: str
    platform: str
    profile_digests: tuple[str, ...]
    toolchain: str
    release_profile: str
    source_date_epoch: int

    def __post_init__(self) -> None:
        _validate_request(self)


def build_input_identity(source_root: Path, request: BuildRequest) -> BuildInputIdentityV2:
    _validate_request(request)
    revision, tree, cargo, pnpm = _stable_snapshot(source_root)
    return BuildInputIdentityV2("build-input-v2", revision, tree, request.release_version, request.target, request.platform, request.profile_digests, request.toolchain, cargo, pnpm, request.release_profile, request.source_date_epoch)


def preflight_candidate(source_root: Path, candidate_root: Path, build: BuildInputIdentityV2) -> None:
    _validate_build(build)
    source_before, candidate_before = _capture_repository(source_root), _capture_repository(candidate_root)
    try:
        source_after, candidate_after = _capture_repository(source_root), _capture_repository(candidate_root)
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.INPUT_MUTATION_DETECTED, "snapshot_second_capture_failed") from error
    if (source_before, candidate_before) != (source_after, candidate_after):
        raise ReleaseFailure(FailureCodeV1.INPUT_MUTATION_DETECTED, "repository_snapshot_changed")
    _require_source_matches(build, source_before)
    if candidate_before != source_before:
        raise ReleaseFailure(FailureCodeV1.CANDIDATE_IDENTITY_MISMATCH, "candidate_snapshot_mismatch")


def _stable_snapshot(root: Path) -> tuple[str, str, str, str]:
    first = _capture_repository(root)
    try:
        second = _capture_repository(root)
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.INPUT_MUTATION_DETECTED, "snapshot_second_capture_failed") from error
    if first != second:
        raise ReleaseFailure(FailureCodeV1.INPUT_MUTATION_DETECTED, "repository_snapshot_changed")
    return first


def _capture_repository(root: Path) -> tuple[str, str, str, str]:
    return capture_repository(root).as_tuple()


def _snapshot(root: Path, unused: FailureCodeV1) -> tuple[str, str, str, str]:
    return _capture_repository(root)


def _validate_request(request: object) -> None:
    if type(request) is not BuildRequest:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "build_request_invalid")
    _validate_fields(request.release_version, request.target, request.platform, request.profile_digests, request.toolchain, request.release_profile, request.source_date_epoch)


def _validate_build(build: object) -> None:
    if type(build) is not BuildInputIdentityV2:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "build_identity_invalid")
    if build.schema_version != "build-input-v2" or not _REVISION.fullmatch(build.source_revision):
        raise ReleaseFailure(FailureCodeV1.SOURCE_REVISION_INVALID, "source_revision_invalid")
    try:
        validate_sha256(build.source_tree_sha256)
        validate_sha256(build.cargo_lock_sha256)
        validate_sha256(build.pnpm_lock_sha256)
    except ReleaseFailure as error:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "build_digest_invalid") from error
    _validate_fields(build.release_version, build.target, build.platform, build.profile_digests, build.toolchain, build.release_profile, build.source_date_epoch)


def _validate_fields(release_version: object, target: object, platform: object, profile_digests: object, toolchain: object, release_profile: object, source_date_epoch: object) -> None:
    if (type(release_version) is not str or not _VERSION.fullmatch(release_version) or type(target) is not str or type(platform) is not str or type(toolchain) is not str or type(release_profile) is not str or target not in _TARGETS or platform not in _PLATFORMS or toolchain not in _TOOLCHAINS or release_profile not in _RELEASE_PROFILES or type(source_date_epoch) is not int or source_date_epoch < 0 or type(profile_digests) is not tuple):
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "build_fields_invalid")
    try:
        for digest in profile_digests:
            validate_sha256(digest)
        if not profile_digests or profile_digests != sort_utf8(profile_digests):
            raise ValueError("profile digests")
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.MANIFEST_INVALID, "profile_digests_invalid") from error


def _require_source_matches(build: BuildInputIdentityV2, source: tuple[str, str, str, str]) -> None:
    if build.source_revision != source[0]:
        raise ReleaseFailure(FailureCodeV1.SOURCE_REVISION_INVALID, "source_revision_mismatch")
    if (build.source_tree_sha256, build.cargo_lock_sha256, build.pnpm_lock_sha256) != source[1:]:
        raise ReleaseFailure(FailureCodeV1.CANDIDATE_IDENTITY_MISMATCH, "source_digest_mismatch")
