import hashlib
import json
import os
import subprocess

from scripts.tests.release_test_support import (
    SCRIPT_PATH,
    SUPPORTED_TARGET,
    ReleaseTestCase,
    bash_native_path,
    run_bash,
)


class PackageReleaseTests(ReleaseTestCase):
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
        candidate_name = f"runne-runtime-1.2.3-{SUPPORTED_TARGET}"
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
