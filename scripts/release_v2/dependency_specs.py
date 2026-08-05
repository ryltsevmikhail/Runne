import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from scripts.release_v2.dependencies_common import fail, public_locator


_VERSION = re.compile(r"(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?")
_PNPM_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_REVISION = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class CargoDependencySpec:
    owner: tuple[str, str]
    name: str
    package: str
    version: str | None
    source: str
    locator: str | None = None
    revision: str | None = None

    def matches(self, key: tuple[str, str, str | None]) -> bool:
        if key[0] != self.package or not _cargo_version_matches(self.version, key[1]):
            return False
        if self.source == "path":
            return key[2] is None
        if self.source == "registry":
            return key[2] == "registry+https://github.com/rust-lang/crates.io-index"
        return key[2] == f"git+{self.locator}#{self.revision}"


def cargo_specs(manifests: tuple[Path, ...]) -> tuple[CargoDependencySpec, ...]:
    rows = [(path, _toml(path)) for path in manifests if path.name == "Cargo.toml"]
    workspace = next((data.get("workspace") for _, data in rows if "workspace" in data), {})
    if type(workspace) is not dict:
        raise fail("cargo_workspace_invalid")
    workspace_deps = workspace.get("dependencies", {})
    if type(workspace_deps) is not dict:
        raise fail("cargo_workspace_invalid")
    packages = {_package_key(data, workspace): path for path, data in rows if _package_key(data, workspace)}
    dirs = {os.path.normpath(str(path.parent)): key for key, path in packages.items()}
    result = []
    for path, data in rows:
        owner = _package_key(data, workspace)
        if owner is not None:
            result.extend(_specs(owner, path, data, workspace_deps, dirs))
    return tuple(result)


def pnpm_specifier(name: str, value: str) -> str:
    if not isinstance(name, str) or type(value) is not str:
        raise fail("pnpm_specifier_invalid")
    if _PNPM_VERSION.fullmatch(value):
        return value
    if value.startswith("workspace:"):
        suffix = value[10:]
        if suffix == "*" or _PNPM_VERSION.fullmatch(suffix):
            return value
    if value.startswith("link:") and _relative(value[5:]):
        return value
    if value.startswith("npm:"):
        target, version = value[4:].rsplit("@", 1) if "@" in value[4:] else ("", "")
        if target and _PNPM_VERSION.fullmatch(version):
            return value
    raise fail("pnpm_specifier_invalid")


def _specs(owner: tuple[str, str], path: Path, data: dict[str, object], workspace: dict[str, object], dirs: dict[str, tuple[str, str]]) -> list[CargoDependencySpec]:
    result = []
    for name, value in _dependencies(data).items():
        if type(name) is not str:
            raise fail("cargo_dependency_invalid")
        if type(value) is dict and value.get("workspace") is True:
            if set(value) - {"workspace", "features", "default-features", "optional"} or name not in workspace:
                raise fail("cargo_workspace_dependency_missing")
            value = workspace[name]
        result.append(_spec(owner, path, name, value, dirs))
    if len({item.name for item in result}) != len(result):
        raise fail("cargo_dependency_duplicate")
    return result


def _spec(owner: tuple[str, str], path: Path, name: str, value: object, dirs: dict[str, tuple[str, str]]) -> CargoDependencySpec:
    if type(value) is str:
        return CargoDependencySpec(owner, name, name, _cargo_version(value), "registry")
    if type(value) is not dict or set(value) - {"version", "package", "path", "git", "rev", "features", "default-features", "optional"}:
        raise fail("cargo_dependency_invalid")
    package = value.get("package", name)
    if type(package) is not str:
        raise fail("cargo_dependency_invalid")
    if "path" in value:
        target = dirs.get(os.path.normpath(str(path.parent / _relative_path(value["path"]))))
        if target is None or target[0] != package:
            raise fail("cargo_path_dependency_missing")
        version = _cargo_version(value["version"]) if "version" in value else target[1]
        if not _cargo_version_matches(version, target[1]) or set(value) - {"version", "package", "path", "features", "default-features", "optional"}:
            raise fail("cargo_path_dependency_missing")
        return CargoDependencySpec(owner, name, package, target[1], "path")
    if "git" in value:
        locator, revision = public_locator(_string(value["git"])), _string(value.get("rev"))
        if not _REVISION.fullmatch(revision) or set(value) - {"version", "package", "git", "rev", "features", "default-features", "optional"}:
            raise fail("git_revision_unpinned")
        return CargoDependencySpec(owner, name, package, _cargo_version(value["version"]) if "version" in value else None, "git", locator, revision)
    if "registry" in value:
        raise fail("cargo_registry_unsupported")
    return CargoDependencySpec(owner, name, package, _cargo_version(value.get("version")), "registry")


def _dependencies(data: dict[str, object]) -> dict[str, object]:
    result = {}
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        value = data.get(section, {})
        if type(value) is not dict:
            raise fail("cargo_dependency_invalid")
        result.update(value)
    target = data.get("target", {})
    if type(target) is not dict:
        raise fail("cargo_dependency_invalid")
    for table in target.values():
        if type(table) is not dict:
            raise fail("cargo_dependency_invalid")
        result.update(_dependencies(table))
    return result


def _package_key(data: dict[str, object], workspace: dict[str, object]) -> tuple[str, str] | None:
    package = data.get("package")
    if package is None:
        return None
    if type(package) is not dict or type(package.get("name")) is not str:
        raise fail("cargo_manifest_invalid")
    version = package.get("version")
    if version == {"workspace": True}:
        metadata = workspace.get("package", {})
        version = metadata.get("version") if type(metadata) is dict else None
    return package["name"], _string(version)


def _cargo_version(value: object) -> str:
    value = _string(value)
    bare = value[1:] if value.startswith("=") else value
    if not _VERSION.fullmatch(bare):
        raise fail("cargo_version_unsupported")
    return value


def _cargo_version_matches(spec: str | None, actual: str) -> bool:
    if spec is None or not _PNPM_VERSION.fullmatch(actual):
        return spec is None
    requested = [int(part) for part in spec.removeprefix("=").split(".")]
    version = [int(part) for part in actual.split(".")]
    if spec.startswith("="):
        return len(requested) == 3 and requested == version
    if version[:len(requested)] < requested:
        return False
    if requested[0] or len(requested) == 1:
        upper = [requested[0] + 1, 0, 0]
    elif requested[1] or len(requested) == 2:
        upper = [0, requested[1] + 1, 0]
    else:
        upper = [0, 0, requested[2] + 1]
    return version < upper


def _toml(path: Path) -> dict[str, object]:
    try:
        value = tomllib.loads(path.read_text())
    except Exception as error:
        raise fail("cargo_manifest_invalid") from error
    if type(value) is not dict:
        raise fail("cargo_manifest_invalid")
    return value


def _relative(value: str) -> bool:
    return bool(value) and not value.startswith("/") and "\\" not in value and os.path.normpath(value) not in (".", "..")


def _relative_path(value: object) -> str:
    value = _string(value)
    if not _relative(value):
        raise fail("workspace_path_invalid")
    return value


def _string(value: object) -> str:
    if type(value) is not str or not value:
        raise fail("dependency_value_invalid")
    return value
