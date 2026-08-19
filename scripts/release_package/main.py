#!/usr/bin/env python3
"""Assemble a deterministic local release candidate."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


MODULE_DIR = Path(__file__).parent
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$"
)
PLATFORMS = {
    "aarch64-apple-darwin": "macos",
    "x86_64-apple-darwin": "macos",
    "x86_64-unknown-linux-gnu": "linux",
    "aarch64-unknown-linux-gnu": "linux",
    "x86_64-pc-windows-msvc": "windows",
}


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def parse_arguments(arguments: list[str]) -> tuple[str, str, Path]:
    values: dict[str, str] = {}
    iterator = iter(arguments)
    for option in iterator:
        if option not in {"--version", "--target", "--output"}:
            fail(f"unknown option: {option}")
        if option in values:
            fail(f"duplicate option: {option}")
        try:
            values[option] = next(iterator)
        except StopIteration:
            raise SystemExit(
                f"Usage: {sys.argv[0]} --version <semver> --target <target> --output <empty-directory>"
            ) from None
    if set(values) != {"--version", "--target", "--output"}:
        raise SystemExit(
            f"Usage: {sys.argv[0]} --version <semver> --target <target> --output <empty-directory>"
        )
    return values["--version"], values["--target"], Path(values["--output"])


def command_output(arguments: list[str]) -> str:
    try:
        return subprocess.check_output(arguments, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        fail("must run inside a Git worktree")


def run_module(name: str, *arguments: object) -> str:
    result = subprocess.run(
        [sys.executable, str(MODULE_DIR / name), *(str(argument) for argument in arguments)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return result.stdout.strip()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def profile_paths() -> list[Path]:
    profiles = sorted(Path("docs/profiles").glob("*.json"), key=lambda path: str(path))
    if not profiles:
        fail("at least one profile artifact is required")
    for profile in profiles:
        sidecar = profile.with_suffix(".digest")
        if not sidecar.is_file():
            fail(f"missing profile digest sidecar: {sidecar}")
        if sidecar.read_text(encoding="utf-8").strip("\r\n") != f"sha256:{sha256_file(profile)}":
            fail(f"profile digest mismatch: {profile}")
    return profiles


def validate_environment(version: str, target: str, output: Path) -> tuple[str, str, int]:
    if not SEMVER.fullmatch(version):
        fail("version must be SemVer without build metadata")
    platform = PLATFORMS.get(target)
    if platform is None:
        fail(f"unsupported target: {target}")
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not epoch.isdigit():
        fail("SOURCE_DATE_EPOCH must be set to a non-negative integer")
    if output.exists() and not output.is_dir():
        fail("output path must be a directory")
    if output.is_dir() and any(output.iterdir()):
        fail("output directory must be empty")
    return platform, epoch, int(epoch)


def validate_repository() -> str:
    root = command_output(["git", "rev-parse", "--show-toplevel"])
    os.chdir(root)
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "--verify", "HEAD^{commit}"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        fail("HEAD must resolve to an exact commit")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        fail("HEAD must be a lowercase 40-hex commit SHA")
    if subprocess.run(["git", "diff", "--quiet"]).returncode or subprocess.run(
        ["git", "diff", "--cached", "--quiet"]
    ).returncode:
        fail("tracked working tree is dirty")
    for path, message in ((Path("Cargo.lock"), "Cargo.lock"), (Path("LICENSE"), "LICENSE")):
        if not path.is_file():
            fail(f"{message} is required")
    if not Path("docs/profiles").is_dir():
        fail("docs/profiles is required")
    return revision


def sign_macos_binary(binary: Path, repo_root: Path) -> None:
    identity = os.environ.get("RUNNE_MACOS_SIGNING_IDENTITY", "")
    if not identity:
        return
    if sys.platform != "darwin":
        fail("macOS signing requested on a non-Darwin host")
    script = repo_root / "scripts" / "sign-macos-binary.sh"
    subprocess.run([str(script), "--identity", identity, str(binary)], check=True)


def build_candidate(
    version: str, target: str, platform: str, output: Path, revision: str, epoch: int
) -> Path:
    profiles = profile_paths()
    with tempfile.TemporaryDirectory() as temporary:
        profile_list = Path(temporary) / "profiles.txt"
        metadata = Path(temporary) / "profiles.json"
        profile_list.write_text("".join(f"{path}\n" for path in profiles), encoding="utf-8")
        run_module("profile_metadata.py", profile_list, metadata)
        cargo = os.environ.get("CARGO", "cargo")
        subprocess.run([cargo, "build", "--locked", "--release", "-p", "runne-daemon", "--bin", "runne-daemon", "--target", target], check=True)
        binary_name = "runne-daemon.exe" if platform == "windows" else "runne-daemon"
        binary = Path("target") / target / "release" / binary_name
        if not binary.is_file():
            fail(f"required daemon artifact is missing: {binary}")
        if platform == "macos":
            sign_macos_binary(binary, Path.cwd())
        candidate = output / f"runne-runtime-{version}-{target}"
        output.mkdir(parents=True, exist_ok=True)
        if candidate.exists():
            fail("candidate staging directory already exists")
        (candidate / "LICENSES").mkdir(parents=True)
        shutil.copyfile(binary, candidate / binary_name)
        os.chmod(candidate / binary_name, 0o755)
        shutil.copyfile("LICENSE", candidate / "LICENSES/LICENSE")
        os.chmod(candidate / "LICENSES/LICENSE", 0o644)
        (candidate / "profiles").mkdir()
        for profile in profiles:
            shutil.copyfile(profile, candidate / "profiles" / profile.name)
            os.chmod(candidate / "profiles" / profile.name, 0o644)
        run_module("sbom.py", candidate / "sbom.cdx.json", version)
        lock_digest = sha256_file(Path("Cargo.lock"))
        daemon_digest = sha256_file(candidate / binary_name)
        digest = run_module("candidate_digest.py", revision, version, lock_digest)
        run_module("provenance.py", candidate / "provenance-attestation.json", digest, revision, target, daemon_digest, profile_list)
        run_module("checksums.py", candidate)
        run_module("release_manifest.py", candidate, version, target, platform, revision, lock_digest, digest, binary_name, daemon_digest, metadata)
        run_module("normalize_mtime.py", candidate, epoch)
    return candidate


def main() -> int:
    version, target, output = parse_arguments(sys.argv[1:])
    platform, _, epoch = validate_environment(version, target, output)
    revision = validate_repository()
    candidate = build_candidate(version, target, platform, output, revision, epoch)
    print(f"Packaged local assembled candidate: {candidate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
