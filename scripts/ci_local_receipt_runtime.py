"""Trusted executable resolution and closed environment for local gates."""

from __future__ import annotations

import hashlib
import os
import pwd
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from scripts.ci_local_receipt_common import LocalInputReceiptError
from scripts.rc0_candidate.verify_rust_inventory import _valid_toolchain


_RUST_VERSIONS = {"pinned": "1.97.1", "msrv": "1.95.0"}
_EXECUTABLE_KEYS = {
    "bash", "python3", "rustup", "node", "pnpm",
    "pinned_rustc", "pinned_cargo", "msrv_rustc", "msrv_cargo",
}
_RECORD_KEYS = {"path", "sha256", "version"}


@dataclass(frozen=True)
class TrustedRuntime:
    bash: Path
    environment: dict[str, str]
    executables: dict[str, dict[str, str]]
    toolchains: dict[str, str]


def valid_executable_shape(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != _EXECUTABLE_KEYS:
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


def resolve_trusted_runtime() -> TrustedRuntime:
    account = pwd.getpwuid(os.geteuid())
    home = Path(account.pw_dir).resolve(strict=True)
    cargo_home = home / ".cargo"
    rustup_home = home / ".rustup"
    system_bin = Path("/usr/bin")
    for directory in (home, cargo_home, cargo_home / "bin", rustup_home, system_bin):
        _trusted_directory(directory)

    bash = _trusted_file(system_bin / "bash")
    python = _trusted_file(system_bin / "python3")
    rustup = _trusted_file(cargo_home / "bin/rustup")
    base_environment = _base_environment(home, cargo_home, rustup_home)

    records = {
        "bash": _record(bash, (bash, "--version"), base_environment),
        "python3": _record(python, (python, "--version"), base_environment),
        "rustup": _record(rustup, (rustup, "--version"), base_environment),
    }
    toolchains: dict[str, str] = {}
    toolchain_bins: dict[str, Path] = {}
    for lane, version in _RUST_VERSIONS.items():
        rustc = _rust_tool(rustup, rustup_home, version, "rustc", base_environment)
        cargo = _rust_tool(rustup, rustup_home, version, "cargo", base_environment)
        rustc_record = _record(rustc, (rustc, "-V"), base_environment)
        cargo_record = _record(cargo, (cargo, "-V"), base_environment)
        identity = rustc_record["version"]
        if not _valid_toolchain(identity) or identity.split()[1] != version:
            raise LocalInputReceiptError("canonical Rust toolchain identity changed")
        if not cargo_record["version"].startswith(f"cargo {version} "):
            raise LocalInputReceiptError("canonical Cargo toolchain identity changed")
        records[f"{lane}_rustc"] = rustc_record
        records[f"{lane}_cargo"] = cargo_record
        toolchains[lane] = identity
        toolchain_bins[lane] = rustc.parent

    node, pnpm = _node_and_pnpm(home, base_environment)
    records["node"] = _record(node, (node, "--version"), base_environment)
    records["pnpm"] = _record(pnpm, (node, pnpm, "--version"), base_environment)
    if records["pnpm"]["version"] != "11.10.0":
        raise LocalInputReceiptError("canonical pnpm version changed")
    if _node_major(records["node"]["version"]) < 22:
        raise LocalInputReceiptError("canonical Node.js version is unsupported")

    path = os.pathsep.join(
        (
            os.fspath(toolchain_bins["pinned"]),
            os.fspath(node.parent),
            os.fspath(cargo_home / "bin"),
            os.fspath(system_bin),
        )
    )
    environment = {
        **base_environment,
        "PATH": path,
        "GOCODE_TRUSTED_BASH": os.fspath(bash),
        "GOCODE_TRUSTED_PYTHON": os.fspath(python),
        "GOCODE_TRUSTED_RUSTUP": os.fspath(rustup),
        "GOCODE_TRUSTED_NODE": os.fspath(node),
        "GOCODE_TRUSTED_PNPM": os.fspath(pnpm),
        "GOCODE_PINNED_TOOLCHAIN_BIN": os.fspath(toolchain_bins["pinned"]),
        "GOCODE_MSRV_TOOLCHAIN_BIN": os.fspath(toolchain_bins["msrv"]),
    }
    tmpdir = os.environ.get("TMPDIR")
    if tmpdir is not None:
        environment["TMPDIR"] = os.fspath(_private_tmpdir(Path(tmpdir)))
    return TrustedRuntime(bash, environment, records, toolchains)


def _base_environment(home: Path, cargo_home: Path, rustup_home: Path) -> dict[str, str]:
    return {
        "HOME": os.fspath(home),
        "CARGO_HOME": os.fspath(cargo_home),
        "RUSTUP_HOME": os.fspath(rustup_home),
        "PATH": "/usr/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "NPM_CONFIG_USERCONFIG": "/dev/null",
        "NPM_CONFIG_GLOBALCONFIG": "/dev/null",
    }


def _trusted_directory(path: Path) -> None:
    try:
        absolute = path.absolute()
        canonical = path.resolve(strict=True)
        metadata = os.stat(canonical, follow_symlinks=False)
    except OSError as error:
        raise LocalInputReceiptError("trusted executable directory is unavailable") from error
    allowed_owner = metadata.st_uid in {0, os.geteuid()}
    allowed_group_write = metadata.st_uid == os.geteuid() and metadata.st_gid == os.getegid()
    if (
        absolute != canonical
        or not stat.S_ISDIR(metadata.st_mode)
        or not allowed_owner
        or metadata.st_mode & stat.S_IWOTH
        or (metadata.st_mode & stat.S_IWGRP and not allowed_group_write)
    ):
        raise LocalInputReceiptError("trusted executable directory is unsafe")


def _trusted_file(path: Path) -> Path:
    try:
        canonical = path.resolve(strict=True)
        metadata = os.stat(canonical, follow_symlinks=False)
    except OSError as error:
        raise LocalInputReceiptError("trusted executable is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & stat.S_IWOTH
        or not metadata.st_mode & stat.S_IXUSR
    ):
        raise LocalInputReceiptError("trusted executable is unsafe")
    return canonical


def _record(path: Path, command: tuple[object, ...], environment: dict[str, str]) -> dict[str, str]:
    path = _trusted_file(path)
    try:
        process = subprocess.run(
            tuple(os.fspath(item) for item in command),
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        version = (process.stdout or process.stderr).splitlines()[0].strip()
    except (OSError, subprocess.SubprocessError, IndexError) as error:
        raise LocalInputReceiptError("trusted executable identity is unavailable") from error
    digest = hashlib.sha256()
    try:
        with path.open("rb", buffering=0) as stream:
            while chunk := stream.read(1 << 20):
                digest.update(chunk)
    except OSError as error:
        raise LocalInputReceiptError("trusted executable cannot be hashed") from error
    return {"path": os.fspath(path), "sha256": digest.hexdigest(), "version": version}


def _rust_tool(
    rustup: Path, rustup_home: Path, version: str, tool: str, environment: dict[str, str]
) -> Path:
    try:
        output = subprocess.run(
            (rustup, "which", "--toolchain", version, tool),
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        ).stdout.strip()
        resolved = Path(output).resolve(strict=True)
        resolved.relative_to(rustup_home / "toolchains")
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise LocalInputReceiptError("canonical Rust tool is unavailable") from error
    _trusted_directory(resolved.parent)
    return _trusted_file(resolved)


def _node_and_pnpm(home: Path, environment: dict[str, str]) -> tuple[Path, Path]:
    root = home / ".nvm/versions/node"
    _trusted_directory(root)
    candidates: list[tuple[tuple[int, ...], Path, Path]] = []
    for node_path in root.glob("*/bin/node"):
        try:
            node = _trusted_file(node_path)
            _trusted_directory(node.parent)
            pnpm = _trusted_file(node.parent / "pnpm")
            version = _run((node, "--version"), environment)
            pnpm_version = _run((node, pnpm, "--version"), environment)
            parsed = tuple(int(part) for part in version.removeprefix("v").split("."))
        except (LocalInputReceiptError, OSError, ValueError):
            continue
        if parsed[0] >= 22 and pnpm_version == "11.10.0":
            candidates.append((parsed, node, pnpm))
    if not candidates:
        raise LocalInputReceiptError("canonical Node.js and pnpm are unavailable")
    _, node, pnpm = max(candidates, key=lambda candidate: candidate[0])
    return node, pnpm


def _run(command: tuple[object, ...], environment: dict[str, str]) -> str:
    try:
        result = subprocess.run(
            tuple(os.fspath(item) for item in command),
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise LocalInputReceiptError("trusted executable version is unavailable") from error
    return (result.stdout or result.stderr).strip()


def _private_tmpdir(path: Path) -> Path:
    try:
        absolute = path.absolute()
        canonical = path.resolve(strict=True)
        metadata = os.stat(canonical, follow_symlinks=False)
    except OSError as error:
        raise LocalInputReceiptError("TMPDIR is unavailable") from error
    if (
        absolute != canonical
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise LocalInputReceiptError("TMPDIR is not owner-private mode 0700")
    return canonical


def _node_major(version: str) -> int:
    match = re.fullmatch(r"v([0-9]+)\.[0-9]+\.[0-9]+", version)
    if match is None:
        raise LocalInputReceiptError("canonical Node.js version is invalid")
    return int(match.group(1))


def _hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
