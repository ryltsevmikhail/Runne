"""Fresh, exactly-cleaned execution namespace for the canonical local gate."""

from __future__ import annotations

import contextlib
import os
import shlex
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from scripts.ci_local_receipt_common import LocalInputReceiptError
from scripts.ci_local_receipt_runtime import TrustedRuntime


@dataclass(frozen=True)
class ExecutionNamespace:
    bash: Path
    environment: dict[str, str]


@contextlib.contextmanager
def execution_namespace(runtime: TrustedRuntime) -> Iterator[ExecutionNamespace]:
    location = Path(tempfile.mkdtemp(prefix="gocode-local-gate-", dir=runtime.tmpdir))
    allowed_dirs: set[Path] = {Path(".")}
    allowed_links: set[Path] = set()
    allowed_files = {
        Path("cargo/.package-cache"), Path("cargo/.package-cache-mutate"),
        Path("cargo/.global-cache"),
    }
    scratch_roots = {Path("tmp"), Path("xdg-cache"), Path("home/.fontconfig")}
    try:
        paths = _directories(location, allowed_dirs)
        _link_commands(location, runtime, allowed_links)
        registry = runtime.account_home / ".cargo/registry"
        if registry.is_dir():
            _symlink(registry, location / "cargo/registry", location, allowed_links)
        environment = _environment(runtime, paths)
        yield ExecutionNamespace(runtime.bash, environment)
    except (OSError, LocalInputReceiptError):
        raise
    finally:
        _exact_cleanup(location, allowed_dirs, allowed_links, allowed_files, scratch_roots)


def _directories(root: Path, allowed: set[Path]) -> dict[str, Path]:
    names = (
        "home", "cargo", "rustup", "tmp", "xdg-config", "xdg-cache",
        "xdg-data", "xdg-state", "base-shim", "pinned-shim", "msrv-shim",
    )
    paths: dict[str, Path] = {}
    for name in names:
        path = root / name
        path.mkdir(mode=0o700)
        allowed.add(Path(name))
        paths[name] = path
    font_cache = paths["home"] / ".fontconfig"
    font_cache.mkdir(mode=0o700)
    allowed.add(Path("home/.fontconfig"))
    return paths


def _link_commands(
    root: Path, runtime: TrustedRuntime, allowed: set[Path]
) -> None:
    base = root / "base-shim"
    for name, target in runtime.base_commands.items():
        _symlink(target, base / name, root, allowed)
    for lane, commands in runtime.rust_commands.items():
        shim = root / f"{lane}-shim"
        for name, target in commands.items():
            _symlink(target, shim / name, root, allowed)


def _symlink(target: Path, link: Path, root: Path, allowed: set[Path]) -> None:
    canonical = target.resolve(strict=True)
    os.symlink(canonical, link)
    allowed.add(link.relative_to(root))


def _environment(runtime: TrustedRuntime, paths: dict[str, Path]) -> dict[str, str]:
    base_path = os.pathsep.join((os.fspath(paths["base-shim"]), "/usr/bin"))
    pinned_path = os.pathsep.join((os.fspath(paths["pinned-shim"]), base_path))
    environment = {
        "PATH": pinned_path,
        "HOME": os.fspath(paths["home"]),
        "CARGO_HOME": os.fspath(paths["cargo"]),
        "RUSTUP_HOME": os.fspath(paths["rustup"]),
        "TMPDIR": os.fspath(paths["tmp"]),
        "XDG_CONFIG_HOME": os.fspath(paths["xdg-config"]),
        "XDG_CACHE_HOME": os.fspath(paths["xdg-cache"]),
        "XDG_DATA_HOME": os.fspath(paths["xdg-data"]),
        "XDG_STATE_HOME": os.fspath(paths["xdg-state"]),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "NODE_DISABLE_COMPILE_CACHE": "1",
        "CARGO_NET_OFFLINE": "true", "CARGO_INCREMENTAL": "0",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_COUNT": "0",
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat", "PAGER": "cat",
        "NPM_CONFIG_USERCONFIG": "/dev/null", "NPM_CONFIG_GLOBALCONFIG": "/dev/null",
        "npm_config_userconfig": "/dev/null", "npm_config_globalconfig": "/dev/null",
        "PNPM_HOME": os.fspath(paths["home"] / "pnpm-home"),
        "PNPM_STORE_DIR": os.fspath(runtime.account_home / ".local/share/pnpm/store/v11"),
        "PLAYWRIGHT_BROWSERS_PATH": os.fspath(runtime.account_home / ".cache/ms-playwright"),
        "GOCODE_TRUSTED_BASH": os.fspath(runtime.bash),
        "GOCODE_TRUSTED_PYTHON": os.fspath(runtime.base_commands["python3"]),
        "GOCODE_TRUSTED_NODE": os.fspath(runtime.base_commands["node"]),
        "GOCODE_PINNED_TOOLCHAIN_BIN": os.fspath(paths["pinned-shim"]),
        "GOCODE_MSRV_TOOLCHAIN_BIN": os.fspath(paths["msrv-shim"]),
    }
    pnpm = Path(runtime.executables["pnpm"]["path"])
    environment["GOCODE_TRUSTED_PNPM"] = os.fspath(pnpm)
    for name, path in runtime.frontend.items():
        environment[f"GOCODE_FRONTEND_{name.upper()}"] = os.fspath(path)
    if runtime.frontend:
        node = os.fspath(runtime.base_commands["node"])
        vite = os.fspath(runtime.frontend["vite"])
        environment["GOCODE_PLAYWRIGHT_WEB_SERVER_COMMAND"] = (
            f"cd apps/desktop && {shlex.quote(node)} {shlex.quote(vite)} --host 127.0.0.1"
        )
    return environment


def _exact_cleanup(
    root: Path,
    allowed_dirs: set[Path],
    allowed_links: set[Path],
    allowed_files: set[Path],
    scratch_roots: set[Path],
) -> None:
    try:
        actual_dirs, actual_links, actual_files = _inventory(root)
        scratch_entries = {
            relative for relative in actual_dirs | actual_links | actual_files
            if any(relative == prefix or prefix in relative.parents for prefix in scratch_roots)
        }
        if (
            not (actual_dirs - scratch_entries).issubset(allowed_dirs)
            or not (actual_links - scratch_entries).issubset(allowed_links)
            or not (actual_files - scratch_entries).issubset(allowed_files)
        ):
            raise LocalInputReceiptError(f"execution namespace cleanup refused: {root}")
        for relative in sorted(actual_files | actual_links, key=lambda item: len(item.parts), reverse=True):
            os.unlink(root / relative)
        for relative in sorted(actual_dirs - {Path(".")}, key=lambda item: len(item.parts), reverse=True):
            os.rmdir(root / relative)
        os.rmdir(root)
    except LocalInputReceiptError:
        raise
    except OSError as error:
        raise LocalInputReceiptError(f"execution namespace cleanup failed: {root}") from error


def _inventory(root: Path) -> tuple[set[Path], set[Path], set[Path]]:
    directories, links, files = {Path(".")}, set(), set()
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(root)
                metadata = entry.stat(follow_symlinks=False)
                if metadata.st_uid != os.geteuid():
                    raise LocalInputReceiptError("execution namespace owner changed")
                if stat.S_ISLNK(metadata.st_mode):
                    links.add(relative)
                elif stat.S_ISDIR(metadata.st_mode):
                    directories.add(relative)
                    pending.append(path)
                else:
                    files.add(relative)
    return directories, links, files
