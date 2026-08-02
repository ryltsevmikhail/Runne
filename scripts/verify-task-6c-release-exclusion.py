#!/usr/bin/env python3
"""Exercise Task 6C release exclusion with a fake, recording Cargo."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
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


def run(command: list[str], cwd: pathlib.Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, check=True, text=True, capture_output=True)


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
    path.write_text(
        "#!/usr/bin/env bash\nset -eu\nprintf '%s\\0' \"$@\" > \"$CARGO_ARGV\"\n"
        "mkdir -p target/aarch64-apple-darwin/release\n"
        "printf daemon > target/aarch64-apple-darwin/release/gocode-daemon\n" + forbidden,
        encoding="utf-8",
    )
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
        ["bash", "scripts/package-release.sh", "--version", "1.0.0", "--target", TARGET, "--output", str(output)],
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
        bin_dir = root / "bin"
        bin_dir.mkdir()
        fake_cargo = bin_dir / "cargo"
        fake_git = bin_dir / "git"
        fake_git.write_text(
            "#!/usr/bin/env bash\nset -eu\nargs=(\"$@\")\n"
            "if [ \"${args[0]:-}\" = \"-C\" ]; then args=(\"${args[@]:2}\"); fi\n"
            "case \"${args[*]}\" in\n"
            "  'rev-parse --show-toplevel') pwd ;;\n"
            "  'rev-parse --verify HEAD^{commit}') printf '%040d\\n' 0 ;;\n"
            "  'diff --quiet'|'diff --cached --quiet') exit 0 ;;\n"
            "  *) exit 1 ;;\nesac\n",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        argv_path = root / "cargo-argv"
        env = os.environ | {
            "CARGO": str(fake_cargo),
            "CARGO_ARGV": str(argv_path),
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
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
        verify = ["bash", "scripts/verify-release.sh", "--fixture-only", "--candidate", str(candidate)]
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
