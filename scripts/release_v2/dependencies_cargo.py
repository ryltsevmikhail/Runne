import hashlib
import re

from scripts.release_v2.canonical import sort_utf8, validate_sha256
from scripts.release_v2.dependencies_common import fail, public_locator, string, strings
from scripts.release_v2.dependency_specs import CargoDependencySpec
from scripts.release_v2.dependencies_types import DependencyPackageV1
from scripts.release_v2.dependencies_workspace import WorkspaceInputs


_GIT_REVISION = re.compile(r"[0-9a-f]{40}")


def cargo_packages(lock: dict[str, object], workspace: WorkspaceInputs, specs: tuple[CargoDependencySpec, ...]) -> list[DependencyPackageV1]:
    if set(lock) - {"version", "package"} or lock.get("version") not in (3, 4) or type(lock.get("package")) is not list:
        raise fail("cargo_lock_invalid")
    records: dict[tuple[str, str, str | None], dict[str, object]] = {}
    for row in lock["package"]:
        if type(row) is not dict or set(row) - {"name", "version", "source", "checksum", "dependencies"}:
            raise fail("cargo_package_invalid")
        source = row.get("source")
        source = string(source) if source is not None else None
        key = (string(row.get("name")), string(row.get("version")), source)
        if key in records:
            raise fail("dependency_duplicate_lock")
        records[key] = row
    direct = _direct(records, specs)
    result = []
    for key, row in records.items():
        refs = tuple(sort_utf8(_reference(value, records) for value in strings(row.get("dependencies", []))))
        locator, digest = _source(key, row, workspace)
        license_name = workspace.cargo.get(key[:2], (None, b"", ""))[0] if key[2] is None else None
        result.append(DependencyPackageV1("cargo", key[0], key[1], locator, digest, license_name, refs, key in direct))
    return result


def _direct(records: dict[tuple[str, str, str | None], dict[str, object]], specs: tuple[CargoDependencySpec, ...]) -> set[tuple[str, str, str | None]]:
    result = set()
    by_owner: dict[tuple[str, str], list[CargoDependencySpec]] = {}
    for spec in specs:
        by_owner.setdefault(spec.owner, []).append(spec)
    for owner, declared in by_owner.items():
        row = records.get((*owner, None))
        if row is None:
            raise fail("workspace_lock_missing")
        edges = [_key(value, records) for value in strings(row.get("dependencies", []))]
        if len(edges) != len(declared) or len(set(edges)) != len(edges):
            raise fail("cargo_direct_edge_mismatch")
        for edge in edges:
            matches = [spec for spec in declared if spec.matches(edge)]
            if len(matches) != 1:
                raise fail("dependency_source_mismatch")
            result.add(edge)
    return result


def _reference(value: str, records: dict[tuple[str, str, str | None], dict[str, object]]) -> str:
    key = _key(value, records)
    return f"cargo:{key[0]}@{key[1]}"


def _key(value: str, records: dict[tuple[str, str, str | None], dict[str, object]]) -> tuple[str, str, str | None]:
    match = re.fullmatch(r"([^ ]+)(?: ([^ ]+))?(?: \(([^)]+)\))?", value)
    if match is None:
        raise fail("dependency_closure_incomplete")
    candidates = [key for key in records if key[0] == match[1] and (match[2] is None or key[1] == match[2]) and (match[3] is None or key[2] == match[3])]
    if len(candidates) != 1:
        raise fail("dependency_source_mismatch")
    return candidates[0]


def _source(key: tuple[str, str, str | None], row: dict[str, object], workspace: WorkspaceInputs) -> tuple[str, str]:
    source, checksum = key[2], row.get("checksum")
    if source is None:
        manifest = workspace.cargo.get(key[:2])
        if manifest is None or checksum is not None:
            raise fail("workspace_metadata_missing")
        return manifest[2], hashlib.sha256(manifest[1]).hexdigest()
    if source.startswith("registry+"):
        if type(checksum) is not str:
            raise fail("registry_checksum_missing")
        return public_locator(source[9:]), validate_sha256(checksum)
    if source.startswith("git+"):
        locator, separator, revision = source[4:].partition("#")
        if not separator or not _GIT_REVISION.fullmatch(revision) or checksum is not None:
            raise fail("git_revision_unpinned")
        return public_locator(locator), revision
    raise fail("dependency_source_invalid")
