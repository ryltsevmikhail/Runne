#!/usr/bin/env python3
"""Exercise Task 6C release exclusion with a fake, recording Cargo."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = "aarch64-apple-darwin"
ALLOWLIST = {
    "LICENSES/LICENSE",
    "checksums.sha256",
    "gocode-daemon",
    "profiles/example.json",
    "provenance-attestation.json",
    "release-manifest.v1.json",
    "sbom.cdx.json",
}
FORBIDDEN_ARTIFACTS = ("activation_process", "recovery_process")


def bash_executable() -> str:
    """Resolve Git Bash instead of the WSL launcher on native Windows."""
    if os.name != "nt":
        executable = shutil.which("bash")
        if executable:
            return executable
        raise SystemExit("Task 6C fixture requires bash")
    git_executable = shutil.which("git")
    candidates = []
    if git_executable:
        candidates.append(pathlib.Path(git_executable).resolve().parent.parent / "bin/bash.exe")
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(pathlib.Path(program_files) / "Git/bin/bash.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise SystemExit("Task 6C fixture requires Git Bash on Windows")


def run(command: list[str], cwd: pathlib.Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command, cwd=cwd, env=env, check=True, text=True, capture_output=True
        )
    except subprocess.CalledProcessError as error:
        if error.stdout:
            print(error.stdout, file=sys.stderr, end="")
        if error.stderr:
            print(error.stderr, file=sys.stderr, end="")
        raise


def files(candidate: pathlib.Path) -> set[str]:
    return {path.relative_to(candidate).as_posix() for path in candidate.rglob("*") if path.is_file()}


def require_allowlist(candidate: pathlib.Path) -> None:
    actual = files(candidate)
    if actual != ALLOWLIST:
        raise SystemExit(f"Task 6C candidate allowlist mismatch: {sorted(actual)}")


def write_fake_cargo(path: pathlib.Path, include_forbidden: bool) -> None:
    forbidden = (
        "printf activation > target/aarch64-apple-darwin/release/activation_process\n"
        "printf recovery > target/aarch64-apple-darwin/release/recovery_process\n"
        if include_forbidden
        else ""
    )
    source = (
        "#!/usr/bin/env bash\nset -eu\nprintf 'build\\0' > \"$CARGO_ARGV\"\n"
        "printf '%s\\0' \"$@\" >> \"$CARGO_ARGV\"\n"
        "mkdir -p target/aarch64-apple-darwin/release\n"
        "printf daemon > target/aarch64-apple-darwin/release/gocode-daemon\n" + forbidden
    )
    path.write_bytes(source.encode("utf-8"))
    path.chmod(0o755)


def append_bound_forbidden_artifacts(candidate: pathlib.Path) -> None:
    for name, content in (("activation_process", b"activation"), ("recovery_process", b"recovery")):
        (candidate / name).write_bytes(content)
    manifest_path = candidate / "release-manifest.v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name in FORBIDDEN_ARTIFACTS:
        manifest["artifacts"].append(
            {
                "kind": "forbidden-fixture",
                "path": name,
                "sha256": hashlib.sha256((candidate / name).read_bytes()).hexdigest(),
                "target": TARGET,
            }
        )
    checksums = sorted(
        (
            (path.relative_to(candidate).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
            for path in candidate.rglob("*")
            if path.is_file() and path.name not in {"checksums.sha256", "release-manifest.v1.json"}
        ),
        key=lambda row: row[0].encode("utf-8"),
    )
    checksum_path = candidate / "checksums.sha256"
    checksum_path.write_text("".join(f"{digest}  {name}\n" for name, digest in checksums), encoding="utf-8")
    checksum_digest = hashlib.sha256(checksum_path.read_bytes()).hexdigest()
    for evidence in manifest["evidence"]:
        if evidence["gate_id"] == "checksums":
            evidence["sha256"] = checksum_digest
    manifest_path.write_bytes(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )


def package(root: pathlib.Path, env: dict[str, str], name: str) -> pathlib.Path:
    output = root / name
    run(
        [
            env["CARGO"],
            "scripts/package-release.sh",
            "--version",
            "1.0.0",
            "--target",
            TARGET,
            "--output",
            output.as_posix(),
        ],
        root,
        env,
    )
    return next(output.iterdir())


def copy_release_modules(root: pathlib.Path) -> None:
    """Copy the wrapper dependencies needed by the standalone fixture."""
    scripts = root / "scripts"
    for script in ("package-release.sh", "verify-release.sh", "verify_release.py"):
        shutil.copy2(ROOT / "scripts" / script, scripts / script)
    for package in ("release_package", "release_verify"):
        shutil.copytree(ROOT / "scripts" / package, scripts / package)


def initialize_fixture_repository(root: pathlib.Path, env: dict[str, str]) -> None:
    run(["git", "init"], root, env)
    run(["git", "add", "."], root, env)
    run(
        [
            "git",
            "-c",
            "user.name=GOCODE Fixture",
            "-c",
            "user.email=fixture@gocode.invalid",
            "commit",
            "-m",
            "fixture",
        ],
        root,
        env,
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary) / "fixture"
        (root / "scripts").mkdir(parents=True)
        (root / "docs/profiles").mkdir(parents=True)
        copy_release_modules(root)
        (root / "LICENSE").write_text("fixture\n", encoding="utf-8")
        (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        profile = root / "docs/profiles/example.json"
        profile.write_text('{"profile_id":"fixture","profile_revision":1}\n', encoding="utf-8")
        digest = hashlib.sha256(profile.read_bytes()).hexdigest()
        profile.with_suffix(".digest").write_text(f"sha256:{digest}\n", encoding="utf-8")
        initialize_fixture_repository(root, os.environ.copy())
        fake_cargo = root / "build"
        argv_path = root / "cargo-argv"
        bash = bash_executable()
        env = os.environ | {
            "CARGO": bash,
            # Keep the recorder path relative to the fixture root. Git Bash does
            # not interpret a Windows ``C:/...`` path as absolute inside shell
            # redirections, while the release packager always builds from the
            # resolved repository root.
            "CARGO_ARGV": argv_path.name,
            "SOURCE_DATE_EPOCH": "1",
        }
        write_fake_cargo(fake_cargo, include_forbidden=True)
        candidate = package(root, env, "output-with-forbidden-targets")
        if argv_path.read_bytes().split(b"\0")[:-1] != [
            b"build", b"--locked", b"--release", b"-p", b"gocode-daemon", b"--bin", b"gocode-daemon", b"--target", TARGET.encode()
        ]:
            raise SystemExit("package-release Cargo argv is not daemon package/bin exact")
        require_allowlist(candidate)
        write_fake_cargo(fake_cargo, include_forbidden=False)
        baseline = package(root, env, "output-daemon-only")
        require_allowlist(baseline)
        verify = [
            bash,
            "scripts/verify-release.sh",
            "--fixture-only",
            "--candidate",
            candidate.as_posix(),
        ]
        baseline_report = json.loads(run(verify, root, env).stdout)
        if baseline_report["status"] != "blocked" or "manifest" in baseline_report["blocked_gate_ids"]:
            raise SystemExit("baseline verifier did not block only independent evidence")
        append_bound_forbidden_artifacts(candidate)
        report = json.loads(run(verify, root, env).stdout)
        if report["status"] != "blocked" or "manifest" in report["blocked_gate_ids"]:
            raise SystemExit("bound forbidden artifacts did not preserve generic manifest evidence")
        try:
            require_allowlist(candidate)
        except SystemExit:
            pass
        else:
            raise SystemExit("Task 6C allowlist accepted bound forbidden artifacts")
    print("Task 6C release exclusion passed.")


if __name__ == "__main__":
    main()
