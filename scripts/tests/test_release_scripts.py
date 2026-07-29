import hashlib
import json
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


class PackageReleaseTests(unittest.TestCase):
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
        self.cargo_marker = pathlib.Path(self.temporary_directory.name) / "cargo-invoked"
        cargo = self.bin_directory / "cargo"
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
        environment["CARGO_INVOCATION_MARKER"] = str(self.cargo_marker)
        environment["CARGO"] = bash_native_path(self.bin_directory / "cargo")
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

    def test_rejects_dirty_tracked_tree(self) -> None:
        (self.root / "Cargo.lock").write_text("changed\n", encoding="utf-8")

        result = self.run_package(self.root / "output")

        self.assert_rejected(result, "tracked working tree is dirty")
        self.assertFalse((self.root / "output").exists())

    def test_rejects_nonempty_output_directory(self) -> None:
        output = self.root / "output"
        output.mkdir()
        (output / "existing.txt").write_text("keep\n", encoding="utf-8")

        result = self.run_package(output)

        self.assert_rejected(result, "output directory must be empty")
        self.assertEqual((output / "existing.txt").read_text(encoding="utf-8"), "keep\n")

    def test_rejects_missing_source_date_epoch(self) -> None:
        environment = os.environ.copy()
        environment["PATH"] = f"{self.bin_directory}{os.pathsep}{environment['PATH']}"
        environment.pop("SOURCE_DATE_EPOCH", None)
        result = run_bash(
            SCRIPT_PATH,
            [
                "--version",
                "1.2.3",
                "--target",
                SUPPORTED_TARGET,
                "--output",
                bash_native_path(self.root / "output"),
            ],
            cwd=self.root,
            environment=environment,
        )

        self.assert_rejected(result, "SOURCE_DATE_EPOCH must be set")
        self.assertFalse((self.root / "output").exists())

    def test_rejects_unsupported_target(self) -> None:
        result = self.run_package(self.root / "output", target="unsupported-target")

        self.assert_rejected(result, "unsupported target")
        self.assertFalse((self.root / "output").exists())

    def test_rejects_profile_digest_mismatch(self) -> None:
        sidecar = self.root / "docs" / "profiles" / "profile-a.digest"
        sidecar.write_text("sha256:" + "0" * 64 + "\n", encoding="utf-8")
        subprocess.run(["git", "add", str(sidecar.relative_to(self.root))], cwd=self.root, check=True)
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
                "invalid profile fixture",
            ],
            cwd=self.root,
            check=True,
        )

        result = self.run_package(self.root / "output")

        self.assert_rejected(result, "profile digest mismatch")
        self.assertFalse((self.root / "output").exists())
        self.assertFalse(self.cargo_marker.exists())

    def test_rejects_malformed_profile_json_before_cargo(self) -> None:
        self.write_profile("profile-a.json", b"{not-json}\n")
        self.commit_profiles("malformed profile fixture")

        result = self.run_package(self.root / "output")

        self.assert_rejected(result, "invalid profile JSON")
        self.assertFalse((self.root / "output").exists())
        self.assertFalse(self.cargo_marker.exists())

    def test_rejects_profile_without_revision_before_cargo(self) -> None:
        self.write_profile("profile-a.json", b'{"profile_id":"fixture-profile"}\n')
        self.commit_profiles("profile without revision fixture")

        result = self.run_package(self.root / "output")

        self.assert_rejected(result, "profile_revision is required")
        self.assertFalse((self.root / "output").exists())
        self.assertFalse(self.cargo_marker.exists())

    def commit_profiles(self, message: str) -> None:
        subprocess.run(["git", "add", "docs/profiles"], cwd=self.root, check=True)
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
                message,
            ],
            cwd=self.root,
            check=True,
        )

    def test_identical_inputs_produce_identical_manifest_and_checksums(self) -> None:
        first_output = self.root / "first-output"
        second_output = self.root / "second-output"

        first = self.run_package(first_output)
        second = self.run_package(second_output)

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        candidate_name = f"gocode-runtime-1.2.3-{SUPPORTED_TARGET}"
        first_candidate = first_output / candidate_name
        second_candidate = second_output / candidate_name
        for name in ("release-manifest.v1.json", "checksums.sha256"):
            self.assertEqual(
                (first_candidate / name).read_bytes(),
                (second_candidate / name).read_bytes(),
            )
        manifest_bytes = (first_candidate / "release-manifest.v1.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        self.assertEqual(
            manifest_bytes,
            json.dumps(
                manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            + b"\n",
        )
        self.assertEqual(manifest["qualification_state"], "assembled")
        self.assertEqual(len(manifest["candidate"]["qualification_lanes"]), 2)
        for lane in manifest["candidate"]["qualification_lanes"]:
            self.assertEqual(len(lane["hosted_execution_slots"]), 3)
            for slot in lane["hosted_execution_slots"]:
                self.assertEqual(slot["status"], "planned")
                self.assertNotIn("hosted_runner", slot)
        self.assertTrue(manifest["evidence"])
        candidate_bytes = json.dumps(
            manifest["candidate"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        expected_candidate_digest = hashlib.sha256(candidate_bytes).hexdigest()
        for evidence in manifest["evidence"]:
            self.assertNotIn("hosted_runner", evidence)
            self.assertNotIn("lane_id", evidence)
            self.assertEqual(evidence["candidate_digest"], expected_candidate_digest)
        checksum_lines = (first_candidate / "checksums.sha256").read_text().splitlines()
        checksum_paths = [line.split("  ", 1)[1] for line in checksum_lines]
        self.assertEqual(checksum_paths, sorted(checksum_paths, key=lambda path: path.encode("utf-8")))
        self.assertFalse(any("release-manifest.v1.json" in line for line in checksum_lines))

class VerifyReleaseTests(PackageReleaseTests):
    def package_candidate(self) -> pathlib.Path:
        output = self.root / "output"
        result = self.run_package(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output / f"gocode-runtime-1.2.3-{SUPPORTED_TARGET}"

    def run_verify(self, candidate: pathlib.Path, fixture_only: bool = False) -> subprocess.CompletedProcess[str]:
        arguments: list[str] = []
        if fixture_only:
            arguments.append("--fixture-only")
        arguments.extend(["--candidate", bash_native_path(candidate)])
        return run_bash(
            VERIFY_SCRIPT_PATH,
            arguments,
            cwd=self.root,
        )

    def snapshot_tree(self, root: pathlib.Path) -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def verify_json(self, candidate: pathlib.Path, fixture_only: bool = False) -> dict:
        result = self.run_verify(candidate, fixture_only)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def make_approved_candidate(self) -> pathlib.Path:
        candidate = self.package_candidate()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        daemon = (candidate / "gocode-daemon").read_bytes()
        targets = {"linux": "x86_64-unknown-linux-gnu", "macos": SUPPORTED_TARGET, "windows": "x86_64-pc-windows-msvc"}
        artifact_paths = {"linux": "linux-daemon", "macos": "gocode-daemon", "windows": "windows-daemon"}
        for platform, path in artifact_paths.items():
            if path != "gocode-daemon":
                (candidate / path).write_bytes(daemon + platform.encode("ascii"))
        artifacts = []
        for platform, path in artifact_paths.items():
            artifacts.append({"kind": "daemon", "path": path, "sha256": hashlib.sha256((candidate / path).read_bytes()).hexdigest(), "target": targets[platform]})
        manifest["artifacts"] = artifacts
        profile_digests = [profile["sha256"] for profile in manifest["profiles"]]
        manifest["platforms"] = [{"artifact_sha256": artifact["sha256"], "os": platform, "profile_digests": profile_digests, "target": targets[platform]} for platform, artifact in zip(artifact_paths, artifacts)]
        for lane in manifest["candidate"]["qualification_lanes"]:
            for slot in lane["hosted_execution_slots"]:
                slot["status"] = "actual"
                slot["hosted_runner"] = {"provider": "fixture-ci", "runner_image": f"{slot['platform']}-image-v1", "run_id": f"{lane['lane_id']}-{slot['platform']}-1"}
        candidate_bytes = json.dumps(manifest["candidate"], sort_keys=True, separators=(",", ":")).encode()
        candidate_digest = hashlib.sha256(candidate_bytes).hexdigest()
        evidence_dir = candidate / "evidence"
        evidence_dir.mkdir()
        def write_payload(name: str, payload: dict) -> tuple[str, str]:
            path = evidence_dir / name
            path.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            return path.relative_to(candidate).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()
        records = []
        def add(kind: str, platform: str, relative: str, sha256: str, **extra: object) -> None:
            artifact = next(item for item in artifacts if item["target"] == targets[platform])
            record = {"artifact_sha256": artifact["sha256"], "candidate_digest": candidate_digest, "gate_id": kind, "kind": kind, "platform": platform, "profile_digests": profile_digests, "sha256": sha256, "source_revision": manifest["candidate"]["source_revision"], "uri": f"candidate://{candidate.name}/{relative}"}
            record.update(extra)
            records.append(record)
        for platform in targets:
            provenance = {"artifact_sha256": next(item["sha256"] for item in artifacts if item["target"] == targets[platform]), "candidate_digest": candidate_digest, "profile_digests": profile_digests, "qualification_lanes": manifest["candidate"]["qualification_lanes"], "source_revision": manifest["candidate"]["source_revision"], "target": targets[platform]}
            relative, value = write_payload(f"provenance-{platform}.json", provenance)
            for kind in ("package", "checksums"):
                add(kind, platform, relative, value)
            add("provenance-attestation", platform, relative, value)
        for lane in manifest["candidate"]["qualification_lanes"]:
            for slot in lane["hosted_execution_slots"]:
                relative, value = write_payload(f"hosted-{lane['lane_id']}-{slot['platform']}.json", {"ok": True})
                for kind in ("hosted-build-test", "hosted-clippy", "hosted-rustdoc", "hosted-docs"):
                    add(kind, slot["platform"], relative, value, cargo_version=lane["cargo_version"], hosted_runner=slot["hosted_runner"], lane_id=lane["lane_id"], rustc_version=lane["rustc_version"])
        compatibility = {"candidate_digest": candidate_digest, "source_revision": manifest["candidate"]["source_revision"], "rows": [{"artifact_sha256": next(item["sha256"] for item in artifacts if item["target"] == targets[platform]), "candidate_digest": candidate_digest, "disposition": "verified", "platform": platform, "profile_digests": profile_digests, "source_revision": manifest["candidate"]["source_revision"]} for platform in targets]}
        relative, value = write_payload("compatibility.json", compatibility)
        add("compatibility", "linux", relative, value)
        supply_chain_payloads = {
            "advisory": {"advisory_database_sha256": "a" * 64, "findings": []},
            "license": {"findings": [], "policy_revision": "fixture-v1"},
            "secret-scan": {"findings": [], "scanner_version": "fixture-v1"},
            "sbom": {"bomFormat": "CycloneDX", "components": [], "specVersion": "1.5"},
            "performance": {"metric_set_sha256": "b" * 64},
            "soak": {"duration_seconds": 60},
            "chaos": {"scenario_set_sha256": "c" * 64},
        }
        for kind, fields in supply_chain_payloads.items():
            if kind == "sbom":
                continue
            payload = {"artifact_sha256": artifacts[0]["sha256"], "candidate_digest": candidate_digest, "outcome": "passed", "profile_digests": profile_digests, "source_revision": manifest["candidate"]["source_revision"], **fields}
            supply_relative, supply_value = write_payload(f"{kind}.json", payload)
            add(kind, "linux", supply_relative, supply_value)
        profile_bindings = [
            {"name": profile["name"], "revision": profile["revision"], "sha256": profile["sha256"]}
            for profile in manifest["profiles"]
        ]
        source_candidate_digest = "d" * 64
        source_candidate_revision = "e" * 40
        source_relative, source_value = write_payload(
            "source-candidate.json",
            {
                "artifacts": [
                    {"platform": platform, "sha256": next(item["sha256"] for item in artifacts if item["target"] == targets[platform])}
                    for platform in targets
                ],
                "candidate_digest": source_candidate_digest,
                "format": "source-candidate-reference.v1",
                "profiles": profile_bindings,
                "source_revision": source_candidate_revision,
            },
        )
        for platform in targets:
            artifact_sha256 = next(item["sha256"] for item in artifacts if item["target"] == targets[platform])
            for kind in ("fresh-install", "upgrade", "rollback"):
                operation_relative, operation_value = write_payload(
                    f"{kind}-{platform}.json",
                    {
                        "candidate_digest": candidate_digest,
                        "destination_artifact_sha256": artifact_sha256,
                        "destination_profiles": profile_bindings,
                        "destination_schema_revision": "release-operation-evidence.v1",
                        "outcome": "passed",
                        "platform": platform,
                        "source_artifact_sha256": artifact_sha256,
                        "source_candidate_digest": source_candidate_digest,
                        "source_candidate_manifest_sha256": source_value,
                        "source_candidate_manifest_uri": f"candidate://{candidate.name}/{source_relative}",
                        "source_candidate_revision": source_candidate_revision,
                        "source_profiles": profile_bindings,
                        "source_revision": manifest["candidate"]["source_revision"],
                        "source_schema_revision": "release-operation-evidence.v1",
                    },
                )
                add(kind, platform, operation_relative, operation_value)
        for platform in targets:
            artifact_sha256 = next(item["sha256"] for item in artifacts if item["target"] == targets[platform])
            sbom_payload = {"artifact_sha256": artifact_sha256, "bomFormat": "CycloneDX", "candidate_digest": candidate_digest, "components": [], "outcome": "passed", "profile_digests": profile_digests, "source_revision": manifest["candidate"]["source_revision"], "specVersion": "1.5"}
            relative, value = write_payload(f"sbom-{platform}.json", sbom_payload)
            add("sbom", platform, relative, value)
            phase_payloads = {
                "phase6b-native-certificate": {"artifact_sha256": artifact_sha256, "candidate_digest": candidate_digest, "containment_outcome": "passed", "native_certificate_sha256": "6" * 64, "outcome": "passed", "platform": platform, "profile_digests": profile_digests, "schema_revision": "phase6b-native-certificate.v1", "source_revision": manifest["candidate"]["source_revision"], "startup_outcome": "passed"},
                "phase8-compatibility": {"artifact_sha256": artifact_sha256, "candidate_digest": candidate_digest, "compatibility_outcome": "passed", "outcome": "passed", "platform": platform, "profile_digests": profile_digests, "profile_name": profile_bindings[0]["name"], "profile_revision": profile_bindings[0]["revision"], "profile_sha256": profile_bindings[0]["sha256"], "schema_revision": "phase8-compatibility-evidence.v1", "source_revision": manifest["candidate"]["source_revision"]},
                "phase9-operations": {"artifact_sha256": artifact_sha256, "candidate_digest": candidate_digest, "evaluation_report_sha256": "9" * 64, "observability_report_sha256": "8" * 64, "operations_report_sha256": "7" * 64, "outcome": "passed", "platform": platform, "profile_digests": profile_digests, "schema_revision": "phase9-operations-evidence.v1", "source_revision": manifest["candidate"]["source_revision"]},
            }
            for kind, payload in phase_payloads.items():
                relative, value = write_payload(f"{kind}-{platform}.json", payload)
                add(kind, platform, relative, value)
        manifest["evidence"] = records
        manifest["qualification_state"] = "approved"
        review_subject = {
            "format": manifest["format"], "candidate": manifest["candidate"], "artifacts": manifest["artifacts"],
            "profiles": manifest["profiles"], "platforms": manifest["platforms"], "evidence": records,
        }
        review_subject_digest = hashlib.sha256(json.dumps(review_subject, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        def attestation(kind, payload):
            issuer = "fixture-review-authority"
            identity_key = "owner_identity" if kind == "owner-approval" else "reviewer_identity"
            subject = {"candidate_digest": candidate_digest, "review_subject_digest": review_subject_digest, "kind": kind, "issuer": issuer, "issuer_identity": payload[identity_key], "role": payload["role"], "decision": payload["decision"], "rubric_version": payload["rubric_version"]}
            return {"format": "release-approval-attestation.v1", "issuer": issuer, "subject": subject, "verification": "external-cryptographic-verification-required"}
        review_packet = {"candidate_digest": candidate_digest, "conflict_declaration": "none", "review_subject_digest": review_subject_digest, "reviewer_identity": "reviewer-a", "role": "security", "rubric_version": "v1"}
        final_review = {"candidate_digest": candidate_digest, "conflict_declaration": "none", "decision": "approved", "review_subject_digest": review_subject_digest, "reviewer_identity": "reviewer-b", "role": "security-reliability", "rubric_version": "v1"}
        final_review["attestation"] = attestation("independent-final-review", final_review)
        owner_approval = {"candidate_digest": candidate_digest, "decision": "approved", "owner_identity": "owner-a", "review_subject_digest": review_subject_digest, "role": "owner", "rubric_version": "v1"}
        owner_approval["attestation"] = attestation("owner-approval", owner_approval)
        for kind, payload in (("review-packet", review_packet), ("independent-final-review", final_review), ("owner-approval", owner_approval)):
            relative, value = write_payload(f"{kind}.json", payload)
            add(kind, "linux", relative, value)
        manifest["evidence"] = records
        manifest["qualification_state"] = "approved"
        checksums = []
        for path in sorted((path for path in candidate.rglob("*") if path.is_file() and path.name not in {"checksums.sha256", "release-manifest.v1.json"}), key=lambda path: path.relative_to(candidate).as_posix().encode()):
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(candidate).as_posix()}\n")
        (candidate / "checksums.sha256").write_text("".join(checksums), encoding="utf-8")
        (candidate / "release-manifest.v1.json").write_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        return candidate

    def write_manifest(self, candidate: pathlib.Path, manifest: dict) -> None:
        (candidate / "release-manifest.v1.json").write_bytes(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )

    def refresh_candidate(self, candidate: pathlib.Path, manifest: dict, changed_kind: str | None = None) -> None:
        if changed_kind:
            for evidence in manifest["evidence"]:
                if evidence["kind"] == changed_kind:
                    path = candidate / evidence["uri"].split(f"candidate://{candidate.name}/", 1)[1]
                    evidence["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        checksums = []
        for path in sorted((path for path in candidate.rglob("*") if path.is_file() and path.name not in {"checksums.sha256", "release-manifest.v1.json"}), key=lambda path: path.relative_to(candidate).as_posix().encode()):
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(candidate).as_posix()}\n")
        (candidate / "checksums.sha256").write_text("".join(checksums), encoding="utf-8")
        self.write_manifest(candidate, manifest)

    def test_changed_archive_file_blocks_without_mutating_inputs(self) -> None:
        candidate = self.package_candidate()
        (candidate / "gocode-daemon").write_bytes(b"altered archive bytes\n")
        source_before = self.snapshot_tree(self.root)
        candidate_before = self.snapshot_tree(candidate)

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("artifact-digest", report["blocked_gate_ids"])
        self.assertEqual(source_before, self.snapshot_tree(self.root))
        self.assertEqual(candidate_before, self.snapshot_tree(candidate))

    def test_malformed_checksum_blocks_without_mutating_inputs(self) -> None:
        candidate = self.package_candidate()
        (candidate / "checksums.sha256").write_text("not a checksum\n", encoding="utf-8")
        source_before = self.snapshot_tree(self.root)
        candidate_before = self.snapshot_tree(candidate)

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("checksums", report["blocked_gate_ids"])
        self.assertEqual(source_before, self.snapshot_tree(self.root))
        self.assertEqual(candidate_before, self.snapshot_tree(candidate))

    def test_checked_in_profile_digest_mismatch_blocks_without_mutating_inputs(self) -> None:
        candidate = self.package_candidate()
        (self.root / "docs" / "profiles" / "profile-a.digest").write_text(
            "sha256:" + "0" * 64 + "\n", encoding="utf-8"
        )
        source_before = self.snapshot_tree(self.root)
        candidate_before = self.snapshot_tree(candidate)

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("profile-integrity", report["blocked_gate_ids"])
        self.assertEqual(source_before, self.snapshot_tree(self.root))
        self.assertEqual(candidate_before, self.snapshot_tree(candidate))

    def test_missing_hosted_platform_evidence_is_explicitly_blocked(self) -> None:
        candidate = self.package_candidate()

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("hosted-platform-evidence", report["blocked_gate_ids"])

    def test_single_platform_assembled_package_is_structurally_accepted_and_blocked(self) -> None:
        candidate = self.package_candidate()

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertNotIn("manifest", report["blocked_gate_ids"])
        self.assertIn("hosted-platform-evidence", report["blocked_gate_ids"])

    def test_fixture_hosted_evidence_cannot_produce_production_verified(self) -> None:
        candidate = self.make_approved_candidate()

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("hosted-platform-evidence", report["blocked_gate_ids"])
        self.assertIn("approval-attestation", report["blocked_gate_ids"])

    def test_review_approval_replay_with_a_different_subject_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "owner-approval.json"
        review = json.loads(review_path.read_text())
        review["review_subject_digest"] = "0" * 64
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "owner-approval")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_final_review_attestation_cannot_be_reused_as_owner_approval(self) -> None:
        candidate = self.make_approved_candidate()
        final_review = json.loads((candidate / "evidence" / "independent-final-review.json").read_text())
        owner_path = candidate / "evidence" / "owner-approval.json"
        owner_approval = json.loads(owner_path.read_text())
        owner_approval["attestation"] = final_review["attestation"]
        owner_path.write_bytes(json.dumps(owner_approval, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "owner-approval")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_review_pending_packet_remains_valid_when_promoted_to_approved(self) -> None:
        candidate = self.make_approved_candidate()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        review_packet_path = candidate / "evidence" / "review-packet.json"
        review_packet = json.loads(review_packet_path.read_text())
        decision_records = [record for record in manifest["evidence"] if record["kind"] in {"independent-final-review", "owner-approval"}]
        decision_bytes = {
            record["kind"]: (candidate / record["uri"].split(f"candidate://{candidate.name}/", 1)[1]).read_bytes()
            for record in decision_records
        }
        for record in decision_records:
            (candidate / record["uri"].split(f"candidate://{candidate.name}/", 1)[1]).unlink()
        manifest["evidence"] = [record for record in manifest["evidence"] if record["kind"] not in {"independent-final-review", "owner-approval"}]
        manifest["qualification_state"] = "review-pending"
        self.refresh_candidate(candidate, manifest)

        pending_report = self.verify_json(candidate, fixture_only=True)

        self.assertNotIn("manifest", pending_report["blocked_gate_ids"])
        self.assertEqual(review_packet["review_subject_digest"], json.loads(review_packet_path.read_text())["review_subject_digest"])

        for record in decision_records:
            path = candidate / record["uri"].split(f"candidate://{candidate.name}/", 1)[1]
            path.write_bytes(decision_bytes[record["kind"]])
        manifest["evidence"].extend(decision_records)
        manifest["qualification_state"] = "approved"
        self.refresh_candidate(candidate, manifest)

        self.assertEqual(self.verify_json(candidate, fixture_only=True), {"blocked_gate_ids": [], "status": "fixture-verified"})

    def test_owner_approval_requires_rubric_and_attestation_subject_fields(self) -> None:
        candidate = self.make_approved_candidate()
        owner_path = candidate / "evidence" / "owner-approval.json"
        owner_approval = json.loads(owner_path.read_text())
        owner_approval.pop("rubric_version")
        owner_path.write_bytes(json.dumps(owner_approval, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "owner-approval")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_fixture_approval_requires_the_closed_fixture_issuer(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "independent-final-review.json"
        review = json.loads(review_path.read_text())
        review["attestation"]["issuer"] = "untrusted-review-authority"
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_later_state_requires_assembled_records_for_each_platform(self) -> None:
        candidate = self.make_approved_candidate()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        manifest["evidence"] = [
            record for record in manifest["evidence"]
            if not (record["kind"] == "sbom" and record["platform"] == "windows")
        ]
        self.refresh_candidate(candidate, manifest)

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_compatibility_payload_cannot_masquerade_as_phase8_evidence(self) -> None:
        candidate = self.make_approved_candidate()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        phase8 = next(record for record in manifest["evidence"] if record["kind"] == "phase8-compatibility")
        compatibility = next(record for record in manifest["evidence"] if record["kind"] == "compatibility")
        phase8["uri"] = compatibility["uri"]
        phase8["sha256"] = compatibility["sha256"]
        self.refresh_candidate(candidate, manifest)

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("phase8-compatibility", report["blocked_gate_ids"])

    def test_compatibility_payload_cannot_masquerade_as_advisory_evidence(self) -> None:
        candidate = self.make_approved_candidate()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        advisory = next(record for record in manifest["evidence"] if record["kind"] == "advisory")
        compatibility = next(record for record in manifest["evidence"] if record["kind"] == "compatibility")
        advisory["uri"] = compatibility["uri"]
        advisory["sha256"] = compatibility["sha256"]
        self.refresh_candidate(candidate, manifest)

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_unsuccessful_supply_chain_payload_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        advisory_path = candidate / "evidence" / "advisory.json"
        advisory = json.loads(advisory_path.read_text())
        advisory["outcome"] = "failed"
        advisory_path.write_bytes(json.dumps(advisory, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "advisory")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_incomplete_compatibility_rows_are_explicitly_blocked(self) -> None:
        candidate = self.make_approved_candidate()
        compatibility_path = candidate / "evidence" / "compatibility.json"
        compatibility = json.loads(compatibility_path.read_text())
        compatibility["rows"].pop()
        compatibility_path.write_bytes(json.dumps(compatibility, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "compatibility")

        report = self.verify_json(candidate)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("compatibility", report["blocked_gate_ids"])

    def test_non_verified_compatibility_row_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        compatibility_path = candidate / "evidence" / "compatibility.json"
        compatibility = json.loads(compatibility_path.read_text())
        compatibility["rows"][0].update({"decision": "scope-v1", "disposition": "unsupported", "rationale": "not in fixture"})
        compatibility_path.write_bytes(json.dumps(compatibility, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "compatibility")

        report = self.verify_json(candidate)

        self.assertIn("compatibility", report["blocked_gate_ids"])

    def test_upgrade_payload_with_different_candidate_digest_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        upgrade_path = candidate / "evidence" / "upgrade-linux.json"
        upgrade = json.loads(upgrade_path.read_text())
        upgrade["candidate_digest"] = "0" * 64
        upgrade_path.write_bytes(json.dumps(upgrade, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "upgrade")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("install-upgrade-rollback", report["blocked_gate_ids"])

    def test_unknown_destination_profile_revision_blocks_before_fixture_promotion(self) -> None:
        candidate = self.make_approved_candidate()
        rollback_path = candidate / "evidence" / "rollback-windows.json"
        rollback = json.loads(rollback_path.read_text())
        rollback["destination_profiles"][0]["revision"] = 999
        rollback_path.write_bytes(json.dumps(rollback, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "rollback")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("install-upgrade-rollback", report["blocked_gate_ids"])

    def test_upgrade_source_artifact_must_match_immutable_source_manifest(self) -> None:
        candidate = self.make_approved_candidate()
        upgrade_path = candidate / "evidence" / "upgrade-macos.json"
        upgrade = json.loads(upgrade_path.read_text())
        upgrade["source_artifact_sha256"] = "0" * 64
        upgrade_path.write_bytes(json.dumps(upgrade, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "upgrade")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("install-upgrade-rollback", report["blocked_gate_ids"])

    def test_rollback_source_profile_must_match_immutable_source_manifest(self) -> None:
        candidate = self.make_approved_candidate()
        rollback_path = candidate / "evidence" / "rollback-linux.json"
        rollback = json.loads(rollback_path.read_text())
        rollback["source_profiles"][0]["revision"] = 999
        rollback_path.write_bytes(json.dumps(rollback, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "rollback")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("install-upgrade-rollback", report["blocked_gate_ids"])

    def test_conflicting_source_profile_digest_for_same_name_and_revision_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        source_path = candidate / "evidence" / "source-candidate.json"
        source = json.loads(source_path.read_text())
        duplicate = dict(source["profiles"][0])
        duplicate["sha256"] = "0" * 64
        source["profiles"].append(duplicate)
        source_path.write_bytes(json.dumps(source, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        source_digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        for evidence in manifest["evidence"]:
            if evidence["kind"] in {"fresh-install", "upgrade", "rollback"}:
                path = candidate / evidence["uri"].split(f"candidate://{candidate.name}/", 1)[1]
                payload = json.loads(path.read_text())
                payload["source_candidate_manifest_sha256"] = source_digest
                payload["source_profiles"] = source["profiles"]
                path.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                evidence["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.refresh_candidate(candidate, manifest)

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("install-upgrade-rollback", report["blocked_gate_ids"])

    def test_fixture_only_structural_candidate_preserves_source_and_candidate_bytes(self) -> None:
        candidate = self.make_approved_candidate()
        source_before = self.snapshot_tree(self.root)
        candidate_before = self.snapshot_tree(candidate)

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report, {"blocked_gate_ids": [], "status": "fixture-verified"})
        self.assertEqual(source_before, self.snapshot_tree(self.root))
        self.assertEqual(candidate_before, self.snapshot_tree(candidate))

    def test_final_review_with_declared_conflict_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "independent-final-review.json"
        review = json.loads(review_path.read_text())
        review["conflict_declaration"] = "employer-conflict"
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_final_review_without_security_and_reliability_coverage_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "independent-final-review.json"
        review = json.loads(review_path.read_text())
        review["role"] = "reliability"
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_normalized_final_reviewer_owner_self_review_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "independent-final-review.json"
        review = json.loads(review_path.read_text())
        review["reviewer_identity"] = "  OWNER-A  "
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_unicode_normalized_final_reviewer_owner_self_review_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        self.assertEqual(
            self.verify_json(candidate, fixture_only=True),
            {"blocked_gate_ids": [], "status": "fixture-verified"},
        )
        final_review_path = candidate / "evidence" / "independent-final-review.json"
        final_review = json.loads(final_review_path.read_text())
        final_review["reviewer_identity"] = "jo\u0308hn"
        final_review_path.write_bytes(
            json.dumps(final_review, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        owner_approval_path = candidate / "evidence" / "owner-approval.json"
        owner_approval = json.loads(owner_approval_path.read_text())
        owner_approval["owner_identity"] = "\u2003JÖHN\u2003"
        owner_approval_path.write_bytes(
            json.dumps(owner_approval, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")
        self.refresh_candidate(candidate, manifest, "owner-approval")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_combined_final_review_bypass_blocks(self) -> None:
        candidate = self.make_approved_candidate()
        review_path = candidate / "evidence" / "independent-final-review.json"
        review = json.loads(review_path.read_text())
        review.update({
            "conflict_declaration": "employer-conflict",
            "reviewer_identity": " Owner-A ",
            "role": "reliability",
        })
        review_path.write_bytes(json.dumps(review, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        manifest = json.loads((candidate / "release-manifest.v1.json").read_text())
        self.refresh_candidate(candidate, manifest, "independent-final-review")

        report = self.verify_json(candidate, fixture_only=True)

        self.assertEqual(report["status"], "blocked")
        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_source_revision_must_match_checked_out_head(self) -> None:
        candidate = self.make_approved_candidate()
        manifest_path = candidate / "release-manifest.v1.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["candidate"]["source_revision"] = "0" * 40
        self.write_manifest(candidate, manifest)

        report = self.verify_json(candidate)

        self.assertIn("source-integrity", report["blocked_gate_ids"])

    def test_unstaged_tracked_source_cannot_verify(self) -> None:
        candidate = self.make_approved_candidate()
        (self.root / "LICENSE").write_text("dirty source\n", encoding="utf-8")

        report = self.verify_json(candidate)

        self.assertIn("source-clean", report["blocked_gate_ids"])

    def test_staged_tracked_source_cannot_verify(self) -> None:
        candidate = self.make_approved_candidate()
        (self.root / "LICENSE").write_text("staged source\n", encoding="utf-8")
        subprocess.run(["git", "add", "LICENSE"], cwd=self.root, check=True)

        report = self.verify_json(candidate)

        self.assertIn("source-clean", report["blocked_gate_ids"])

    def test_empty_actual_hosted_runner_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        manifest_path = candidate / "release-manifest.v1.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["candidate"]["qualification_lanes"][0]["hosted_execution_slots"][0]["hosted_runner"] = {}
        self.write_manifest(candidate, manifest)

        report = self.verify_json(candidate)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_reused_platform_artifact_binding_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        manifest_path = candidate / "release-manifest.v1.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["platforms"][1]["artifact_sha256"] = manifest["platforms"][0]["artifact_sha256"]
        self.write_manifest(candidate, manifest)

        report = self.verify_json(candidate)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_cross_os_target_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        manifest_path = candidate / "release-manifest.v1.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["platforms"][0]["target"] = SUPPORTED_TARGET
        self.write_manifest(candidate, manifest)

        report = self.verify_json(candidate)

        self.assertIn("manifest", report["blocked_gate_ids"])

    def test_duplicate_evidence_identity_with_divergent_bytes_is_rejected(self) -> None:
        candidate = self.make_approved_candidate()
        manifest_path = candidate / "release-manifest.v1.json"
        manifest = json.loads(manifest_path.read_text())
        duplicate = next(record for record in manifest["evidence"] if record["kind"] == "advisory").copy()
        duplicate_path = candidate / "evidence" / "duplicate-advisory.json"
        duplicate_path.write_bytes(b'{"different":true}\n')
        duplicate["uri"] = f"candidate://{candidate.name}/evidence/duplicate-advisory.json"
        duplicate["sha256"] = hashlib.sha256(duplicate_path.read_bytes()).hexdigest()
        manifest["evidence"].append(duplicate)
        self.refresh_candidate(candidate, manifest)

        report = self.verify_json(candidate)

        self.assertIn("manifest", report["blocked_gate_ids"])


if __name__ == "__main__":
    unittest.main()
