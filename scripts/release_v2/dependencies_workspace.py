import fnmatch
import hashlib
import json
import os
import posixpath
import tomllib
from dataclasses import dataclass
from pathlib import Path

from scripts.release_v2.model import FailureCodeV1, ReleaseFailure


@dataclass(frozen=True)
class WorkspaceInputs:
    cargo: dict[tuple[str, str], tuple[str | None, bytes, str]]
    pnpm: dict[tuple[str, str], tuple[str | None, bytes, str, tuple[str, ...]]]
    pnpm_dirs: dict[str, tuple[str, str]]
    pnpm_declared: dict[tuple[str, str], dict[str, str]]
    pnpm_root_declared: dict[str, str]


def read_workspace_manifests(manifests: tuple[Path, ...]) -> WorkspaceInputs:
    cargo_rows, pnpm_rows = _read_rows(manifests)
    cargo = _cargo_workspace(cargo_rows)
    pnpm, dirs, declared, root_declared = _pnpm_workspace(pnpm_rows)
    return WorkspaceInputs(cargo, pnpm, dirs, declared, root_declared)


def link_target(locator: str, importer: str, inputs: WorkspaceInputs) -> tuple[str, str]:
    if not locator.startswith("link:"):
        _fail("pnpm_link_invalid")
    target = _normal_path(posixpath.join(importer, locator[5:]))
    key = inputs.pnpm_dirs.get(target)
    if key is None:
        _fail("pnpm_link_target_missing")
    return key


def _read_rows(manifests: tuple[Path, ...]) -> tuple[list[tuple[Path, bytes, dict[str, object]]], list[tuple[Path, bytes, dict[str, object]]]]:
    cargo, pnpm = [], []
    for path in manifests:
        raw = _read(path)
        if path.name == "Cargo.toml":
            cargo.append((path, raw, _toml(raw)))
        elif path.name == "package.json":
            pnpm.append((path, raw, _json(raw)))
        else:
            _fail("dependency_manifest_invalid")
    return cargo, pnpm


def _cargo_workspace(rows: list[tuple[Path, bytes, dict[str, object]]]) -> dict[tuple[str, str], tuple[str | None, bytes, str]]:
    roots = [(path, data["workspace"]) for path, _, data in rows if "workspace" in data]
    if len(roots) > 1:
        _fail("cargo_workspace_invalid")
    root, workspace = roots[0] if roots else (None, {})
    if type(workspace) is not dict:
        _fail("cargo_workspace_invalid")
    packages = {key: row for row in rows if (key := _cargo_key(row[2], workspace)) is not None}
    if len(packages) != sum(_cargo_key(data, workspace) is not None for _, _, data in rows):
        _fail("dependency_duplicate_manifest")
    members = _cargo_members(root, workspace, packages)
    deps = workspace.get("dependencies", {})
    if type(deps) is not dict:
        _fail("cargo_workspace_invalid")
    dirs = {_path(path.parent): key for key, (path, _, _) in packages.items()}
    for key, (path, _, data) in packages.items():
        if root is not None and key not in members:
            _fail("cargo_workspace_member_missing")
        for name, value in _cargo_dependencies(data).items():
            _cargo_dependency(name, value, path, dirs, deps)
    result = {}
    for key, (path, raw, data) in packages.items():
        member = root is not None and key in members
        result[key] = (_cargo_license(data.get("package"), workspace), raw, f"{'workspace' if member else 'path'}:{key[0]}@{key[1]}")
    return result


def _cargo_key(data: dict[str, object], workspace: dict[str, object]) -> tuple[str, str] | None:
    package = data.get("package")
    if package is None:
        return None
    if type(package) is not dict:
        _fail("cargo_manifest_invalid")
    name = _string(package.get("name"))
    version = package.get("version")
    if type(version) is dict and version == {"workspace": True}:
        workspace_package = workspace.get("package", {})
        version = workspace_package.get("version") if type(workspace_package) is dict else None
    return name, _string(version)


def _cargo_members(root: Path | None, workspace: dict[str, object], packages: dict[tuple[str, str], tuple[Path, bytes, dict[str, object]]]) -> set[tuple[str, str]]:
    if root is None:
        return set(packages)
    members = workspace.get("members", [])
    if type(members) is not list or not all(type(value) is str for value in members):
        _fail("cargo_workspace_invalid")
    available = {_relative(root.parent, path.parent): key for key, (path, _, _) in packages.items()}
    selected: set[tuple[str, str]] = set()
    for pattern in members:
        matches = [key for path, key in available.items() if fnmatch.fnmatchcase(path, pattern)]
        if not matches:
            _fail("cargo_workspace_member_missing")
        selected.update(matches)
    return selected


def _cargo_dependencies(data: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {}
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = data.get(section, {})
        if type(value) is not dict:
            _fail("cargo_dependency_invalid")
        result.update(value)
    target = data.get("target", {})
    if type(target) is not dict:
        _fail("cargo_dependency_invalid")
    for table in target.values():
        if type(table) is not dict:
            _fail("cargo_dependency_invalid")
        result.update(_cargo_dependencies(table))
    return result


def _cargo_dependency(name: object, value: object, path: Path, dirs: dict[str, tuple[str, str]], workspace: dict[str, object]) -> None:
    name = _string(name)
    if type(value) is str:
        return
    if type(value) is not dict:
        _fail("cargo_dependency_invalid")
    if value.get("workspace") is True:
        if name not in workspace:
            _fail("cargo_workspace_dependency_missing")
        return
    if "path" in value:
        target = dirs.get(_path(path.parent / _local_path(_string(value["path"]))))
        if target is None or target[0] != value.get("package", name):
            _fail("cargo_path_dependency_missing")
        return
    if "git" in value or "registry" in value:
        _safe_value(value)
        return
    _safe_value(value)


def _pnpm_workspace(rows: list[tuple[Path, bytes, dict[str, object]]]) -> tuple[dict[tuple[str, str], tuple[str | None, bytes, str, tuple[str, ...]]], dict[str, tuple[str, str]], dict[tuple[str, str], dict[str, str]], dict[str, str]]:
    roots = [path for path, _, data in rows if "workspaces" in data]
    if len(roots) > 1:
        _fail("pnpm_workspace_invalid")
    root = roots[0] if roots else (rows[0][0] if rows else None)
    packages: dict[tuple[str, str], tuple[Path, bytes, dict[str, object]]] = {}
    for path, raw, data in rows:
        if "name" in data:
            key = (_string(data["name"]), _string(data.get("version")))
            if key in packages:
                _fail("dependency_duplicate_manifest")
            packages[key] = (path, raw, data)
    dirs = {_pnpm_path(root.parent, path.parent): key for key, (path, _, _) in packages.items()} if root else {}
    root_data = next((data for path, _, data in rows if path == root), {})
    root_declared = _package_dependencies(root_data) if root is not None and "name" not in root_data else {}
    declared, result = {}, {}
    for key, (path, raw, data) in packages.items():
        values = _package_dependencies(data)
        declared[key] = values
        refs = tuple(sorted((_workspace_ref(name, value, key, path, root, packages, dirs) for name, value in values.items() if value.startswith(("workspace:", "link:"))), key=str.encode))
        result[key] = (_license(data), raw, f"workspace:{key[0]}@{key[1]}", refs)
    return result, dirs, declared, root_declared


def _package_dependencies(data: dict[str, object]) -> dict[str, str]:
    result: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        value = data.get(section, {})
        if type(value) is not dict or not all(type(name) is str and type(spec) is str for name, spec in value.items()):
            _fail("pnpm_package_manifest_invalid")
        result.update(value)
    return result


def _workspace_ref(name: str, value: str, unused: tuple[str, str], path: Path, root: Path | None, packages: dict[tuple[str, str], tuple[Path, bytes, dict[str, object]]], dirs: dict[str, tuple[str, str]]) -> str:
    if value.startswith("workspace:"):
        matches = [key for key in packages if key[0] == name and (value == "workspace:*" or value == f"workspace:{key[1]}")]
        if len(matches) != 1:
            _fail("pnpm_workspace_dependency_missing")
        return f"pnpm:{matches[0][0]}@{matches[0][1]}"
    target = dirs.get(_pnpm_path(root.parent, path.parent / _local_path(value[5:])) if root else "")
    if target is None or target[0] != name:
        _fail("pnpm_link_target_missing")
    return f"pnpm:{target[0]}@{target[1]}"


def _license(data: object) -> str | None:
    return _string(data["license"]) if type(data) is dict and data.get("license") is not None else None


def _cargo_license(package: object, workspace: dict[str, object]) -> str | None:
    if type(package) is not dict:
        return None
    value = package.get("license")
    if type(value) is dict and value == {"workspace": True}:
        metadata = workspace.get("package", {})
        value = metadata.get("license") if type(metadata) is dict else None
    return _string(value) if value is not None else None


def _toml(raw: bytes) -> dict[str, object]:
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except Exception as error:
        raise _error("cargo_manifest_invalid") from error
    return _dict(value, "cargo_manifest_invalid")


def _json(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as error:
        raise _error("pnpm_package_manifest_invalid") from error
    return _dict(value, "pnpm_package_manifest_invalid")


def _safe_value(value: object) -> None:
    if type(value) is str:
        if "://" in value and ("@" in value.split("://", 1)[1].split("/", 1)[0] or "?" in value or "#" in value):
            _fail("dependency_locator_invalid")
    elif type(value) is dict:
        for item in value.values():
            _safe_value(item)


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise _error("dependency_input_unavailable") from error


def _dict(value: object, detail: str) -> dict[str, object]:
    if type(value) is not dict:
        _fail(detail)
    return value


def _string(value: object) -> str:
    if type(value) is not str or not value:
        _fail("dependency_value_invalid")
    return value


def _path(path: Path) -> str:
    return os.path.normpath(str(path))


def _relative(root: Path, path: Path) -> str:
    try:
        return _normal_path(str(path.relative_to(root)))
    except ValueError:
        _fail("workspace_path_invalid")


def _pnpm_path(root: Path, path: Path) -> str:
    try:
        value = str(path.relative_to(root))
    except ValueError:
        _fail("workspace_path_invalid")
    return "." if value == "." else _normal_path(value)


def _local_path(value: str) -> Path:
    if value.startswith("/") or "\\" in value:
        _fail("workspace_path_invalid")
    return Path(value)


def _normal_path(value: str) -> str:
    normalized = posixpath.normpath(value)
    if not normalized or normalized == "." or normalized.startswith(("../", "/")):
        _fail("workspace_path_invalid")
    return normalized


def _error(detail: str) -> ReleaseFailure:
    return ReleaseFailure(FailureCodeV1.DEPENDENCY_INVENTORY_INCOMPLETE, detail)


def _fail(detail: str) -> None:
    raise _error(detail)
