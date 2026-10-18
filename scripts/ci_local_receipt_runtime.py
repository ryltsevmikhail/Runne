"""Resolve every non-root executable/load target bound by the local gate."""

from __future__ import annotations

import hashlib
import os
import pwd
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from scripts.ci_local_receipt_common import LocalInputReceiptError
from scripts.ci_local_receipt_packages import frontend_targets
from scripts.ci_local_receipt_paths import _private_tmpdir
from scripts.rc0_candidate.verify_rust_inventory import _valid_toolchain


_RUST_VERSIONS = {"pinned": "1.97.1", "msrv": "1.95.0"}
_SYSTEM_NAMES = ("bash", "python3", "git", "grep", "sed", "cut", "mktemp", "rm", "dirname", "sh")


def _system_directories() -> tuple[Path, ...]:
    """Root-owned system command directories for the current platform.

    Linux merges every system tool into /usr/bin. macOS keeps a subset
    (bash, rm, sh, chmod and friends) in /bin with the rest in /usr/bin.
    """
    directories = [Path("/usr/bin")]
    if sys.platform == "darwin":
        directories.append(Path("/bin"))
    return tuple(directories)


def _system_command(name: str) -> Path:
    for directory in _system_directories():
        if (directory / name).exists():
            return _trusted_file(directory / name)
    raise LocalInputReceiptError("trusted executable is unavailable")


_RUST_NAMES = ("rustc", "cargo", "rustdoc", "rustfmt", "cargo-fmt", "cargo-clippy", "clippy-driver")
_CORE_KEYS = set(_SYSTEM_NAMES) | {"node", "pnpm"} | {
    f"{lane}_{name.replace('-', '_')}" for lane in _RUST_VERSIONS for name in _RUST_NAMES
}
_FRONTEND_KEYS = {
    "eslint", "vitest", "vue_tsc", "vite", "playwright", "esbuild",
    "playwright_chromium", "playwright_headless_shell",
}
_RECORD_KEYS = {"path", "sha256", "version"}


@dataclass(frozen=True)
class TrustedRuntime:
    bash: Path
    account_home: Path
    base_commands: dict[str, Path]
    rust_commands: dict[str, dict[str, Path]]
    frontend: dict[str, Path]
    executables: dict[str, dict[str, str]]
    toolchains: dict[str, str]
    tmpdir: Path | None


def valid_executable_shape(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    keys = set(value)
    if keys != _CORE_KEYS and keys != _CORE_KEYS | _FRONTEND_KEYS:
        return False
    for record in value.values():
        if (
            not isinstance(record, dict)
            or set(record) != _RECORD_KEYS
            or not isinstance(record["path"], str)
            or not Path(record["path"]).is_absolute()
            or not _hex(record["sha256"])
            or not isinstance(record["version"], str)
            or not record["version"]
            or any(character in record["version"] for character in "\r\n\0")
        ):
            return False
    return True


def resolve_trusted_runtime(root: Path | None = None) -> TrustedRuntime:
    account = pwd.getpwuid(os.geteuid())
    home = Path(account.pw_dir).resolve(strict=True)
    # Container images (the hosted CI rust lane) install the rustup layout
    # under CARGO_HOME/RUSTUP_HOME instead of the user home. Honor the
    # standard environment when it is present; the trust checks below apply
    # unchanged, and the developer-home layout remains the fallback.
    cargo_bin = (
        Path(os.environ["CARGO_HOME"]) if "CARGO_HOME" in os.environ else home / ".cargo"
    ) / "bin"
    rustup_home = (
        Path(os.environ["RUSTUP_HOME"]) if "RUSTUP_HOME" in os.environ else home / ".rustup"
    )
    for directory in (home, cargo_bin, rustup_home, *_system_directories()):
        _trusted_directory(directory)
    base_environment = _identity_environment()
    base_commands = {name: _system_command(name) for name in _SYSTEM_NAMES}
    records = {
        name: _file_record(path, f"system {name}")
        for name, path in base_commands.items()
    }
    rust_commands: dict[str, dict[str, Path]] = {}
    toolchains: dict[str, str] = {}
    for lane, version in _RUST_VERSIONS.items():
        commands = {
            name: _rust_tool(None, rustup_home, version, name, base_environment)
            for name in _RUST_NAMES
        }
        rust_commands[lane] = commands
        for name, path in commands.items():
            key = f"{lane}_{name.replace('-', '_')}"
            records[key] = _file_record(path, f"{name} {version}")
        identity = _run((commands["rustc"], "-V"), base_environment)
        cargo_identity = _run((commands["cargo"], "-V"), base_environment)
        records[f"{lane}_rustc"] = _file_record(commands["rustc"], identity)
        records[f"{lane}_cargo"] = _file_record(commands["cargo"], cargo_identity)
        if not _valid_toolchain(identity) or identity.split()[1] != version:
            raise LocalInputReceiptError("canonical Rust toolchain identity changed")
        if not cargo_identity.startswith(f"cargo {version} "):
            raise LocalInputReceiptError("canonical Cargo toolchain identity changed")
        toolchains[lane] = identity

    node, pnpm = _node_and_pnpm(home, base_environment)
    # pnpm's bootstrap re-executes its launcher and resolves `node` through
    # PATH; expose only the pinned node directory for version probes.
    probe_environment = dict(base_environment)
    probe_environment["PATH"] = os.pathsep.join(
        (os.fspath(node.parent), probe_environment["PATH"])
    )
    records["node"] = _record(node, (node, "--version"), base_environment)
    records["pnpm"] = _record(pnpm, (node, pnpm, "--version"), probe_environment)
    if records["pnpm"]["version"] != "11.10.0" or _node_major(records["node"]["version"]) < 22:
        raise LocalInputReceiptError("canonical Node.js or pnpm version changed")
    _reject_system_shadows((node.parent, cargo_bin))
    base_commands["node"] = node

    frontend: dict[str, Path] = {}
    if root is not None and (root / "pnpm-lock.yaml").is_file():
        frontend = frontend_targets(root, home)
        records.update({name: _file_record(path, name) for name, path in frontend.items()})
    tmpdir = _private_tmpdir(Path(os.environ["TMPDIR"])) if "TMPDIR" in os.environ else None
    return TrustedRuntime(
        base_commands["bash"], home, base_commands, rust_commands, frontend,
        records, toolchains, tmpdir,
    )


def _identity_environment() -> dict[str, str]:
    system_path = os.pathsep.join(os.fspath(directory) for directory in _system_directories())
    return {
        "PATH": system_path, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "HOME": "/var/empty", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "NPM_CONFIG_USERCONFIG": "/dev/null", "NPM_CONFIG_GLOBALCONFIG": "/dev/null",
    }


def _reject_system_shadows(directories: tuple[Path, ...]) -> None:
    for directory in directories:
        for name in _SYSTEM_NAMES:
            try:
                present = (directory / name).exists() or (directory / name).is_symlink()
            except OSError as error:
                raise LocalInputReceiptError("writable executable namespace is unreadable") from error
            if present:
                raise LocalInputReceiptError("writable executable namespace shadows a gate command")


def _trusted_directory(path: Path) -> None:
    try:
        absolute, canonical = path.absolute(), path.resolve(strict=True)
        metadata = os.stat(canonical, follow_symlinks=False)
    except OSError as error:
        raise LocalInputReceiptError("trusted executable directory is unavailable") from error
    own_group = metadata.st_uid == os.geteuid() and metadata.st_gid == os.getegid()
    if (
        absolute != canonical or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & stat.S_IWOTH
        or (metadata.st_mode & stat.S_IWGRP and not own_group)
    ):
        raise LocalInputReceiptError("trusted executable directory is unsafe")


def _trusted_file(path: Path) -> Path:
    try:
        canonical = path.resolve(strict=True)
        metadata = os.stat(canonical, follow_symlinks=False)
    except OSError as error:
        raise LocalInputReceiptError("trusted executable is unavailable") from error
    own_group = metadata.st_uid == os.geteuid() and metadata.st_gid == os.getegid()
    if (
        not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & stat.S_IWOTH
        or (metadata.st_mode & stat.S_IWGRP and not own_group)
        or not metadata.st_mode & stat.S_IXUSR
    ):
        raise LocalInputReceiptError("trusted executable is unsafe")
    return canonical


def _file_record(path: Path, version: str) -> dict[str, str]:
    path, digest = _trusted_file(path), hashlib.sha256()
    try:
        with path.open("rb", buffering=0) as stream:
            while chunk := stream.read(1 << 20):
                digest.update(chunk)
    except OSError as error:
        raise LocalInputReceiptError("trusted executable cannot be hashed") from error
    return {"path": os.fspath(path), "sha256": digest.hexdigest(), "version": version}


def _record(path: Path, command: tuple[object, ...], environment: dict[str, str]) -> dict[str, str]:
    return _file_record(path, _run(command, environment).splitlines()[0].strip())


def _rust_tool(
    _rustup: object, rustup_home: Path, version: str, tool: str, _environment: dict[str, str]
) -> Path:
    candidates = [path for path in rustup_home.glob(f"toolchains/{version}-*/bin/{tool}")]
    if len(candidates) != 1:
        raise LocalInputReceiptError("canonical Rust tool is unavailable or ambiguous")
    _trusted_directory(candidates[0].parent)
    return _trusted_file(candidates[0])


def _node_and_pnpm(home: Path, environment: dict[str, str]) -> tuple[Path, Path]:
    root = home / ".nvm/versions/node"
    _trusted_directory(root)
    candidates: list[tuple[tuple[int, ...], Path, Path]] = []
    rejections: list[str] = []
    for node_path in root.glob("*/bin/node"):
        try:
            node, pnpm = _trusted_file(node_path), _trusted_file(node_path.parent / "pnpm")
            version = _run((node, "--version"), environment)
            parsed = tuple(int(part) for part in version.removeprefix("v").split("."))
            # pnpm re-executes its launcher during bootstrap and resolves `node`
            # through PATH; expose only the pinned node directory for the probe.
            probe_environment = dict(environment)
            probe_environment["PATH"] = os.pathsep.join(
                (os.fspath(node.parent), probe_environment["PATH"])
            )
            if parsed[0] >= 22 and _run(
                (node, pnpm, "--version"), probe_environment
            ) == "11.10.0":
                candidates.append((parsed, node, pnpm))
        except (LocalInputReceiptError, OSError, ValueError) as error:
            rejections.append(f"{node_path.parent.parent.name}: {error}")
            continue
    if not candidates:
        detail = "; ".join(rejections) or "no node installations found"
        raise LocalInputReceiptError(
            f"canonical Node.js and pnpm are unavailable ({detail})")
    _, node, pnpm = max(candidates, key=lambda candidate: candidate[0])
    return node, pnpm


def _run(command: tuple[object, ...], environment: dict[str, str]) -> str:
    try:
        result = subprocess.run(tuple(os.fspath(item) for item in command), check=True,
                                capture_output=True, text=True, env=environment)
        output = (result.stdout or result.stderr).strip()
        if not output:
            raise LocalInputReceiptError("trusted executable version is empty")
        return output
    except (OSError, subprocess.SubprocessError) as error:
        raise LocalInputReceiptError("trusted executable version is unavailable") from error


def _node_major(version: str) -> int:
    match = re.fullmatch(r"v([0-9]+)\.[0-9]+\.[0-9]+", version)
    if match is None:
        raise LocalInputReceiptError("canonical Node.js version is invalid")
    return int(match.group(1))


def _hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
