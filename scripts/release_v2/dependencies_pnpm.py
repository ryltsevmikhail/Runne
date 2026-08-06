import hashlib
import re

from scripts.release_v2.canonical import sort_utf8
from scripts.release_v2.dependencies_common import fail, public_locator, string
from scripts.release_v2.dependency_specs import pnpm_specifier
from scripts.release_v2.dependencies_types import DependencyPackageV1
from scripts.release_v2.dependencies_workspace import WorkspaceInputs, link_target
from scripts.release_v2.pnpm_lock_parser import parse_pnpm_lock


_INTEGRITY = re.compile(r"(?:sha256-[A-Za-z0-9+/]{43}=|sha512-[A-Za-z0-9+/]{86}==)")


def pnpm_packages(raw: str, workspace: WorkspaceInputs) -> list[DependencyPackageV1]:
    data = parse_pnpm_lock(raw)
    if set(data) != {"lockfileVersion", "settings", "importers", "packages", "snapshots"} or data["lockfileVersion"] != "9.0":
        raise fail("pnpm_lock_invalid")
    _settings(data["settings"])
    importers, rows, snapshots = data["importers"], data["packages"], data["snapshots"]
    if not all(type(value) is dict for value in (importers, rows, snapshots)):
        raise fail("pnpm_lock_invalid")
    records = {_key(key): row for key, row in rows.items() if type(key) is str and type(row) is dict}
    if len(records) != len(rows):
        raise fail("pnpm_package_invalid")
    direct = _direct(importers, records, snapshots, workspace)
    result = [DependencyPackageV1("pnpm", key[0], key[1], value[2], hashlib.sha256(value[1]).hexdigest(), value[0], tuple(sort_utf8(value[3] + _workspace_refs(workspace.pnpm_declared[key], records))), key in direct) for key, value in workspace.pnpm.items()]
    for key, row in records.items():
        resolution = row.get("resolution")
        if type(resolution) is not dict or set(resolution) - {"integrity", "tarball"} or type(resolution.get("integrity")) is not str or not _INTEGRITY.fullmatch(resolution["integrity"]):
            raise fail("pnpm_resolution_invalid")
        tarball = resolution.get("tarball")
        locator = f"npm:{key[0]}@{key[1]}" if tarball is None else public_locator(string(tarball))
        related = [snapshot for locator_key, snapshot in snapshots.items() if _key(locator_key) == key]
        if not related:
            related = [{}]
        if not all(type(snapshot) is dict for snapshot in related):
            raise fail("pnpm_snapshot_invalid")
        refs = tuple(sort_utf8(_reference(name, value, records, snapshots, workspace) for snapshot in related for name, value in _dependencies(snapshot).items()))
        result.append(DependencyPackageV1("pnpm", key[0], key[1], locator, resolution["integrity"], None, tuple(dict.fromkeys(refs)), key in direct))
    return result


def _settings(value: object) -> None:
    if type(value) is not dict or set(value) - {"autoInstallPeers", "excludeLinksFromLockfile"} or not all(item in ("true", "false") for item in value.values()):
        raise fail("pnpm_lock_invalid")


def _direct(importers: dict[str, object], records: dict[tuple[str, str], object], snapshots: dict[str, object], workspace: WorkspaceInputs) -> set[tuple[str, str]]:
    result = set()
    declared_paths = {"."} if workspace.pnpm_root_declared else set()
    declared_paths.update(path for path, key in workspace.pnpm_dirs.items() if workspace.pnpm_declared[key])
    for path, importer in importers.items():
        if type(path) is not str or type(importer) is not dict or set(importer) - {"dependencies", "devDependencies", "optionalDependencies"}:
            raise fail("pnpm_importer_invalid")
        declared = _declared(path, workspace)
        locked = {}
        for section in importer.values():
            if type(section) is not dict:
                raise fail("pnpm_importer_invalid")
            for name, value in section.items():
                if type(name) is not str or name in locked:
                    raise fail("pnpm_importer_invalid")
                locked[name] = value
        if set(locked) != set(declared):
            raise fail("pnpm_manifest_importer_mismatch")
        for name, specifier in declared.items():
            value = locked[name]
            if _specifier(name, specifier) != _specifier(name, _importer_specifier(value)):
                raise fail("pnpm_manifest_importer_mismatch")
            result.add(_resolved_key(name, _locator(value), specifier, path, records, snapshots, workspace))
    if declared_paths - set(importers):
        raise fail("pnpm_importer_missing")
    return result


def _locator(value: object) -> str:
    if type(value) is dict and set(value) in ({"specifier", "version"}, {"version"}):
        value = value["version"]
    if type(value) is not str or any(marker in value for marker in ("://", "?", "#")):
        raise fail("pnpm_importer_invalid")
    return value


def _importer_specifier(value: object) -> str:
    if type(value) is not dict or set(value) != {"specifier", "version"}:
        raise fail("pnpm_importer_invalid")
    return string(value["specifier"])


def _specifier(name: str, value: str) -> str:
    value = pnpm_specifier(name, value)
    if value.startswith("workspace:"):
        _workspace_key(name, value, workspace=None)
    return value


def _declared(path: str, workspace: WorkspaceInputs) -> dict[str, str]:
    key = workspace.pnpm_dirs.get(path)
    if key is not None:
        return workspace.pnpm_declared[key]
    if path == ".":
        return workspace.pnpm_root_declared
    raise fail("pnpm_importer_missing")


def _resolved_key(name: str, locator: str, specifier: str, path: str, records: dict[tuple[str, str], object], snapshots: dict[str, object], workspace: WorkspaceInputs) -> tuple[str, str]:
    if specifier.startswith("workspace:"):
        expected = _workspace_key(name, specifier, workspace)
        target = link_target(locator, path, workspace) if locator.startswith("link:") else _workspace_key(name, locator, workspace)
        if target != expected:
            raise fail("pnpm_locator_mismatch")
        return target
    if specifier.startswith("link:"):
        target = link_target(specifier, path, workspace)
        if not locator.startswith("link:") or link_target(locator, path, workspace) != target:
            raise fail("pnpm_locator_mismatch")
        return target
    key = _locator_key(name, locator)
    if key not in records or _snapshot_locator(key, locator) not in snapshots or not _exact_locator(name, specifier, locator):
        raise fail("pnpm_locator_mismatch")
    return key


def _exact_locator(name: str, specifier: str, locator: str) -> bool:
    base = _base_locator(locator[4:] if locator.startswith("npm:") else locator)
    expected = specifier[4:] if specifier.startswith("npm:") else f"{name}@{specifier}"
    return base == expected or (not specifier.startswith("npm:") and base == specifier)


def _dependencies(row: dict[str, object]) -> dict[str, str]:
    allowed = {"dependencies", "optionalDependencies", "peerDependencies", "transitivePeerDependencies", "optional"}
    if set(row) - allowed:
        raise fail("pnpm_snapshot_invalid")
    result = {}
    for section in ("dependencies", "optionalDependencies"):
        value = row.get(section, {})
        if type(value) is not dict or not all(type(name) is str and type(locator) is str for name, locator in value.items()):
            raise fail("pnpm_snapshot_invalid")
        result.update(value)
    return result


def _workspace_refs(declared: dict[str, str], records: dict[tuple[str, str], object]) -> tuple[str, ...]:
    result = []
    for name, locator in declared.items():
        if not locator.startswith(("workspace:", "link:")):
            key = _locator_key(name, locator)
            if key not in records:
                raise fail("dependency_closure_incomplete")
            result.append(f"pnpm:{key[0]}@{key[1]}")
    return tuple(result)


def _reference(name: str, locator: str, records: dict[tuple[str, str], object], snapshots: dict[str, object], workspace: WorkspaceInputs) -> str:
    if locator.startswith("workspace:"):
        key = _workspace_key(name, locator, workspace)
    else:
        key = _locator_key(name, locator)
        if key not in records:
            raise fail("dependency_closure_incomplete")
        if "(" in locator and _snapshot_locator(key, locator) not in snapshots:
            raise fail("pnpm_snapshot_invalid")
    return f"pnpm:{key[0]}@{key[1]}"


def _workspace_key(name: str, locator: str, workspace: WorkspaceInputs | None) -> tuple[str, str]:
    if workspace is None:
        if locator == "workspace:*" or (locator.startswith("workspace:") and _key(f"{name}@{locator[10:]}") == (name, locator[10:])):
            return name, locator[10:]
        raise fail("pnpm_workspace_dependency_missing")
    matches = [key for key in workspace.pnpm if key[0] == name and (locator == "workspace:*" or locator == f"workspace:{key[1]}")]
    if len(matches) != 1:
        raise fail("pnpm_workspace_dependency_missing")
    return matches[0]


def _snapshot_locator(key: tuple[str, str], locator: str) -> str:
    return _identity_locator(key[0], locator)


def _locator_key(name: str, locator: str) -> tuple[str, str]:
    return _key(_identity_locator(name, locator))


def _identity_locator(name: str, locator: str) -> str:
    value = locator[4:] if locator.startswith("npm:") else locator
    return value if "@" in _base_locator(value) else f"{name}@{value}"


def _base_locator(value: str) -> str:
    return value.split("(", 1)[0]


def _key(value: object) -> tuple[str, str]:
    if type(value) is not str or "@" not in value:
        raise fail("pnpm_package_invalid")
    name, version = _base_locator(value).rsplit("@", 1)
    if not name or not version or any(character.isspace() for character in value):
        raise fail("pnpm_package_invalid")
    return name, version
