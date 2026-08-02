import hashlib
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "package-release.sh"
VERIFY_SCRIPT_PATH = pathlib.Path(__file__).parents[1] / "verify-release.sh"
SUPPORTED_TARGET = "aarch64-apple-darwin"


def bash_executable() -> str:
    if os.name != "nt":
        executable = shutil.which("bash")
        if executable:
            return executable
        raise RuntimeError("Bash executable is required")
    git_executable = shutil.which("git")
    candidates = []
    if git_executable:
        candidates.append(pathlib.Path(git_executable).resolve().parent.parent / "bin" / "bash.exe")
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(pathlib.Path(program_files) / "Git" / "bin" / "bash.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("Git Bash executable is required on Windows")


def bash_native_path(path: pathlib.Path) -> str:
    resolved = path.resolve().as_posix()
    if os.name == "nt" and len(resolved) >= 3 and resolved[1:3] == ":/":
        return f"/{resolved[0].lower()}{resolved[2:]}"
    return resolved


def run_bash(
    script: pathlib.Path,
    arguments: list[str],
    *,
    cwd: pathlib.Path,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    bash_arguments = [bash_executable()]
    bash_arguments.extend(
        [
            "-c",
            'cd "$1" && shift && shell=$1 && shift && exec "$shell" "$@"',
            "--",
            bash_native_path(cwd),
            bash_native_path(pathlib.Path(bash_executable())),
            bash_native_path(script),
            *arguments,
        ]
    )
    return subprocess.run(
        bash_arguments,
        env=environment,
        text=True,
        capture_output=True,
    )


class ReleaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = pathlib.Path(self.temporary_directory.name) / "repository"
        self.root.mkdir()
        (self.root / "docs" / "profiles").mkdir(parents=True)
        (self.root / "target").mkdir()
        (self.root / "Cargo.lock").write_text("# fixture lockfile\n", encoding="utf-8")
        (self.root / "LICENSE").write_text("fixture license\n", encoding="utf-8")
        (self.root / ".gitattributes").write_text(
            "docs/profiles/*.json text eol=lf\n"
            "docs/profiles/*.digest text eol=lf\n",
            encoding="utf-8",
        )
        self.write_profile(
            "profile-a.json",
            b'{"profile_id":"fixture-profile","profile_revision":1}\n',
        )

        subprocess.run(["git", "init", "--quiet"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Release Test",
                "-c",
                "user.email=release-test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
            cwd=self.root,
            check=True,
        )

        self.bin_directory = pathlib.Path(self.temporary_directory.name) / "bin"
        self.bin_directory.mkdir()
        self.cargo_marker = self.root / "cargo-invoked"
        cargo = self.root / "build"
        cargo.write_bytes(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "target=\"\"\n"
            "while [ $# -gt 0 ]; do\n"
            "  if [ \"$1\" = \"--target\" ]; then target=$2; shift 2; continue; fi\n"
            "  shift\n"
            "done\n"
            "if [ -n \"${CARGO_INVOCATION_MARKER:-}\" ]; then printf invoked > \"$CARGO_INVOCATION_MARKER\"; fi\n"
            "mkdir -p \"target/$target/release\"\n"
            "printf 'fixture daemon\\n' > \"target/$target/release/gocode-daemon\"\n"
            .encode("utf-8")
        )
        cargo.chmod(0o755)

    def write_profile(self, name: str, contents: bytes) -> None:
        profile = self.root / "docs" / "profiles" / name
        profile.write_bytes(contents)
        profile.with_suffix(".digest").write_text(
            f"sha256:{hashlib.sha256(contents).hexdigest()}\n", encoding="utf-8"
        )

    def run_package(self, output: pathlib.Path, target: str = SUPPORTED_TARGET):
        environment = os.environ.copy()
        environment["PATH"] = f"{self.bin_directory}{os.pathsep}{environment['PATH']}"
        environment["SOURCE_DATE_EPOCH"] = "1700000000"
        environment["CARGO_INVOCATION_MARKER"] = self.cargo_marker.name
        environment["CARGO"] = bash_executable()
        return run_bash(
            SCRIPT_PATH,
            [
                "--version",
                "1.2.3",
                "--target",
                target,
                "--output",
                bash_native_path(output),
            ],
            cwd=self.root,
            environment=environment,
        )

    def assert_rejected(self, result: subprocess.CompletedProcess[str], message: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
