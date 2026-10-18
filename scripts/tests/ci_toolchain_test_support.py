"""Shared mock harness for the scripts/ci.sh toolchain-selection tests.

Tiny /bin/sh mock shims stand in for rustc, cargo, rustup, proxies and the
gate commands so scripts/ci.sh runs end-to-end in a controlled subprocess
without executing the real Rust workspace. The rustup and proxy mocks
emulate rustup >= 1.29 network auto-install (marker file under RUSTUP_HOME)
and honor the documented RUSTUP_AUTO_INSTALL=0 opt-out, so a missing export
or an unwanted fetch attempt is observable.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PINNED = ("pinned", "1.97.1", "rustc 1.97.1 (8bab26f4f 2026-07-14)",
          "cargo 1.97.1 (8bab26f4f 2026-07-14)")
MSRV = ("msrv", "1.95.0", "rustc 1.95.0 (000000000 2026-01-01)",
        "cargo 1.95.0 (000000000 2026-01-01)")
LISTING = "1.97.1-x86_64-unknown-linux-gnu (default)"
TOOLCHAIN = "1.97.1-x86_64-unknown-linux-gnu"
_BASH = shutil.which("bash") or "/usr/bin/bash"


def _executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o700)


def _q(value: object) -> str:
    return shlex.quote(str(value))


def _recorder(calls: Path, body: str = "exit 0\n") -> str:
    return f"#!/bin/sh\nprintf '%s\\n' \"$0 $*\" >> {_q(calls)}\n{body}"


def _tool_mock(version_line: str, calls: Path, compiler_log: Path | None = None
               ) -> str:
    record_compiler = ""
    if compiler_log is not None:
        # Only gate-time invocations record the compiler cargo would use;
        # the --version probes run before selection and must not pollute it.
        record_compiler = (
            "    *)\n"
            f"        printf '%s\\n' \"${{RUSTC:-$(command -v rustc || true)}}\""
            f" >> {_q(compiler_log)}\n"
            "        ;;\n"
        )
    return (
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$0 $*\" >> {_q(calls)}\n"
        "case \"$1\" in\n"
        f"    --version) printf '%s\\n' {_q(version_line)} ;;\n"
        "    -vV) printf 'host: mock-host\\n' ;;\n"
        f"{record_compiler}"
        "esac\n"
        "case \"$1\" in\n"
        "    build)\n"
        "        /usr/bin/mkdir -p target/mock-host/release\n"
        "        printf staged > target/mock-host/release/runned\n"
        "        printf staged > target/mock-host/release/runne ;;\n"
        "esac\n"
        "exit 0\n"
    )


def _proxy_mock(version_line: str, calls: Path) -> str:
    # Emulates a rustup proxy for a missing toolchain: with auto-install
    # enabled it fetches (marker under RUSTUP_HOME) and then runs; with
    # RUSTUP_AUTO_INSTALL=0 it refuses without any write or fetch.
    return (
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$0 $*\" >> {_q(calls)}\n"
        "if [ \"${RUSTUP_AUTO_INSTALL:-1}\" != \"0\" ]; then\n"
        "    /usr/bin/mkdir -p \"$RUSTUP_HOME/downloads\" 2>/dev/null || true\n"
        "    : > \"$RUSTUP_HOME/downloads/auto-install-marker\" 2>/dev/null || true\n"
        f"    printf '%s\\n' {_q(version_line)}\n"
        "    exit 0\n"
        "fi\n"
        "echo 'error: toolchain is not installed' >&2\n"
        "exit 1\n"
    )


def _rustup_mock(calls: Path, listing: str, installed_name: str,
                 resolved_cargo: Path | None = None, list_rc: int = 0) -> str:
    resolved = resolved_cargo if resolved_cargo is not None else Path(
        f"/nonexistent/toolchains/{installed_name}/bin/cargo")
    return (
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$0 $*\" >> {_q(calls)}\n"
        "if [ \"$1\" = toolchain ] && [ \"$2\" = list ]; then\n"
        f"    printf '%s\\n' {_q(listing)}\n"
        f"    exit {list_rc}\n"
        "fi\n"
        "if [ \"$1\" = which ]; then\n"
        "    if [ \"$3\" != " + _q(installed_name) + " ]; then\n"
        "        if [ \"${RUSTUP_AUTO_INSTALL:-1}\" = \"0\" ]; then exit 1; fi\n"
        "        /usr/bin/mkdir -p \"$RUSTUP_HOME/downloads\" 2>/dev/null || true\n"
        "        : > \"$RUSTUP_HOME/downloads/auto-install-marker\""
        " 2>/dev/null || true\n"
        "    fi\n"
        f"    printf '%s\\n' {_q(resolved)}\n"
        "    exit 0\n"
        "fi\n"
        "exit 0\n"
    )


def _mock_bin(base: Path, rustc_line: str | None, cargo_line: str | None,
              *, proxy_line: str | None = None, compiler_log: Path | None = None
              ) -> tuple[Path, Path]:
    bin_dir = base / "mock-bin"
    bin_dir.mkdir(mode=0o700)
    calls = base / "calls.log"
    for tool, line in (("rustc", rustc_line), ("cargo", cargo_line)):
        if line is None and proxy_line is not None:
            _executable(bin_dir / tool, _proxy_mock(proxy_line, calls))
        elif line is not None:
            _executable(bin_dir / tool, _tool_mock(line, calls, compiler_log))
    for name, body in (
        ("python3", ""),
        ("bash", ""),
        ("uname", "printf 'Linux\\n'\n"),
        ("git", "printf '%s\\n' '0000000000000000000000000000000000000000'\n"),
    ):
        _executable(bin_dir / name, _recorder(calls, f"{body}exit 0\n"))
    return bin_dir, calls


def _rustup_bin(base: Path, bin_dir: Path, listing: str, installed_name: str,
                resolved_cargo: Path | None = None, list_rc: int = 0) -> Path:
    _executable(bin_dir / "rustup", _rustup_mock(
        base / "rustup-calls.log", listing, installed_name,
        resolved_cargo, list_rc))
    return base / "rustup-calls.log"


def _fallback_tools(base: Path, calls: Path, rustc_line: str,
                    cargo_line: str, name: str = TOOLCHAIN,
                    resolved_cargo: Path | None = None,
                    compiler_log: Path | None = None) -> Path:
    root = base / "toolchain-root"
    tool_dir = root / "toolchains" / name / "bin"
    tool_dir.mkdir(parents=True, mode=0o700)
    _executable(tool_dir / "rustc", _tool_mock(rustc_line, calls, compiler_log))
    _executable(tool_dir / "cargo", _tool_mock(cargo_line, calls, compiler_log))
    return resolved_cargo or (tool_dir / "cargo")


def _stage_ci_fixture(scripts: Path, dist: Path,
                      toolchain_file: str | None = None) -> None:
    scripts.mkdir(parents=True, exist_ok=True)
    for name in ("ci.sh", "ci-toolchain-select.sh", "macos-ci-keychain.sh"):
        (scripts / name).write_text(
            (ROOT / "scripts" / name).read_text(encoding="utf-8"), encoding="utf-8")
    (dist / "assets").mkdir(parents=True, exist_ok=True)
    (dist / "index.html").write_text("<html></html>", encoding="utf-8")
    if toolchain_file is not None:
        (scripts.parent / "rust-toolchain.toml").write_text(
            toolchain_file, encoding="utf-8")


def _lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def _system_bin(base: Path) -> Path:
    sys_dir = base / "system-bin"
    sys_dir.mkdir(mode=0o700)
    for name in ("sed", "cut", "dirname"):
        os.symlink(f"/usr/bin/{name}", sys_dir / name)
    return sys_dir


def _run_ci(base: Path, bin_dir: Path, mode: str, rustc_env: str | None = None,
            path_suffix: str = ":/usr/bin:/bin", toolchain_file: str | None = None
            ) -> tuple[subprocess.CompletedProcess, Path]:
    fixture = base / "fixture"
    _stage_ci_fixture(fixture / "scripts", fixture / "apps/desktop/dist",
                      toolchain_file)
    for name in ("home", "tmp", "rustup-scratch"):
        (base / name).mkdir(exist_ok=True)
    env = {
        "PATH": f"{bin_dir}{path_suffix}",
        "HOME": os.fspath(base / "home"),
        "TMPDIR": os.fspath(base / "tmp"),
        "RUSTUP_HOME": os.fspath(base / "rustup-scratch"),
    }
    if rustc_env is not None:
        env["RUSTC"] = rustc_env
    completed = subprocess.run(
        (_BASH, "scripts/ci.sh", mode), cwd=fixture, env=env,
        capture_output=True, text=True, check=False,
    )
    return completed, base / "rustup-scratch"
