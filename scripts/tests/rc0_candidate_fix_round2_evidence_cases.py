import fcntl
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.tests.test_rc0_candidate_evidence import SOURCE, evidence_module, fixture_records


class Rc0CandidateEvidenceFixRound2Tests(unittest.TestCase):
    def make_evidence_repo(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name) / "repository"
        repo.mkdir()

        def git(*arguments):
            return subprocess.run(
                ["git", "-C", str(repo), *arguments], check=True,
                capture_output=True, text=True,
            ).stdout.strip()

        git("init", "-q")
        git("config", "user.name", "RC0 Fixture")
        git("config", "user.email", "rc0-fixture@example.invalid")
        (repo / "README").write_text("source\n", encoding="utf-8")
        git("add", "README"); git("commit", "-qm", "source")
        source = git("rev-parse", "HEAD")
        evidence = evidence_module()
        target = repo / "docs/evidence/rc0-candidates" / source
        target.mkdir(parents=True)
        for name in evidence.EVIDENCE_FILES:
            (target / name).write_bytes(name.encode("ascii"))
        git("add", "docs/evidence"); git("commit", "-qm", "evidence")
        return repo, source, git("rev-parse", "HEAD")

    def test_persistent_flock_blocks_contender_then_allows_retry(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            lock = root / f".{SOURCE}.construction-lock"
            descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(descriptor, b"1" * 64 + b"\n")
            os.fsync(descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            os.close(descriptor)
            try:
                result = evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            except evidence.EvidenceConstructionError as error:
                self.fail(f"released persistent lock did not permit retry: {error}")
            self.assertEqual(result.directory, root / SOURCE)
            self.assertTrue(lock.is_file())

    def test_completion_marker_is_required_and_binds_exact_directory(self):
        evidence = evidence_module()
        loader = getattr(evidence, "load_completed_fixture_evidence", None)
        self.assertIsNotNone(loader, "completed evidence validator is absent")
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            result = evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertEqual(set(loader(root, SOURCE)), set(evidence.EVIDENCE_FILES))
            marker = root / f".{SOURCE}.complete"
            marker.unlink()
            with self.assertRaises(evidence.EvidenceConstructionError):
                loader(root, SOURCE)
            marker.write_bytes(b"invalid completion authority\n")
            marker.chmod(0o600)
            with self.assertRaises(evidence.EvidenceConstructionError):
                loader(root, SOURCE)
            self.assertTrue(result.directory.is_dir())

    def test_failure_boundaries_release_lock_and_leave_no_accepted_partial_output(self):
        evidence = evidence_module()
        stages = (
            "after-lock", "after-final-create", "after-blob-create",
            "after-blob-write", "after-blob-fsync", "after-directory-fsync",
            "before-marker-publish",
        )
        for selected in stages:
            with self.subTest(stage=selected), tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
                root = Path(output)

                def fail(stage, _root_fd, _source_sha):
                    if stage == selected:
                        raise OSError("injected boundary failure")

                try:
                    evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout), boundary_hook=fail
                    )
                except TypeError as error:
                    self.fail(f"boundary injection API is absent: {error}")
                except evidence.EvidenceConstructionError:
                    pass
                else:
                    self.fail(f"boundary {selected} did not fail")
                self.assertFalse((root / f".{SOURCE}.complete").exists())
                self.assertFalse((root / SOURCE).exists())
                retry = evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
                self.assertEqual(retry.directory, root / SOURCE)

    def test_mixed_authority_output_names_are_excluded(self):
        evidence = evidence_module()
        paths = (
            "dist/verification.json", "verification/results.json",
            "dist/gateverdict.json", "dist/gateoutput.json",
            "dist/VeRiFiCaTiOn-result.json",
            "dist/verification\N{COMBINING ACUTE ACCENT}.json",
        )
        for path in paths:
            records = fixture_records()
            records["artifact-inventory.json"]["artifacts"][0]["relative_path"] = path
            records["checksums.txt"] = records["checksums.txt"].replace(
                b"dist/gocode.tar", path.encode("utf-8")
            )
            records["sbom.spdx.json"]["artifact_bindings"][0]["relative_path"] = path
            with self.subTest(path=path), tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(records, Path(output), Path(checkout))

        records = fixture_records()
        path = "dist/source-gate-results.json"
        records["artifact-inventory.json"]["artifacts"][0]["relative_path"] = path
        records["checksums.txt"] = records["checksums.txt"].replace(
            b"dist/gocode.tar", path.encode("ascii")
        )
        records["sbom.spdx.json"]["artifact_bindings"][0]["relative_path"] = path
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            result = evidence.build_fixture_evidence(records, Path(output), Path(checkout))
            self.assertTrue(result.directory.is_dir())

    def test_failure_after_completion_publish_leaves_valid_completed_namespace(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def fail(stage, _root_fd, _source_sha):
                if stage == "after-marker-publish":
                    raise OSError("injected post-publish failure")

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout), boundary_hook=fail
                )
            self.assertEqual(
                set(evidence.load_completed_fixture_evidence(root, SOURCE)),
                set(evidence.EVIDENCE_FILES),
            )

    def test_evidence_commit_snapshot_detects_root_and_config_replacement(self):
        evidence = evidence_module()
        for mutation in ("root", "config"):
            repo, source, revision = self.make_evidence_repo()

            def replace(stage, captured, selected=mutation):
                if stage != "before-final-recheck":
                    return
                if selected == "root":
                    moved = captured.with_name(captured.name + ".old")
                    captured.rename(moved)
                    shutil.copytree(moved, captured)
                else:
                    config = captured / ".git/config"
                    replacement = captured / ".git/config.new"
                    replacement.write_bytes(config.read_bytes())
                    replacement.replace(config)

            try:
                diagnostics = evidence.validate_fixture_evidence_commit(
                    repo, source, revision, mutation_hook=replace
                )
            except TypeError as error:
                self.fail(f"stable evidence snapshot API is absent: {error}")
            with self.subTest(mutation=mutation):
                self.assertTrue(diagnostics)
                self.assertTrue(any("changed" in item for item in diagnostics))

    def test_lock_open_mode_flock_and_write_errors_close_descriptors(self):
        evidence = evidence_module()
        atomic = __import__("scripts.rc0_candidate.atomic_publish", fromlist=["unused"])
        cases = ("open", "fchmod", "flock", "write")
        for selected in cases:
            with self.subTest(operation=selected), tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
                before = set(os.listdir("/proc/self/fd"))
                if selected == "open":
                    original = atomic.os.open

                    def fail_lock_open(path, *args, **kwargs):
                        if path == f".{SOURCE}.construction-lock":
                            raise OSError("injected lock open failure")
                        return original(path, *args, **kwargs)

                    context = patch.object(atomic.os, "open", side_effect=fail_lock_open)
                elif selected == "fchmod":
                    context = patch.object(atomic.os, "fchmod", side_effect=OSError("injected"))
                elif selected == "flock":
                    context = patch.object(atomic.fcntl, "flock", side_effect=OSError("injected"))
                else:
                    context = patch.object(atomic, "_write_all", side_effect=OSError("injected"))
                with context, self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(
                        fixture_records(), Path(output), Path(checkout)
                    )
                self.assertEqual(before, set(os.listdir("/proc/self/fd")))

    def test_cleanup_refuses_incomplete_namespace_with_changed_owner_token(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def tamper(stage, root_fd, source_sha):
                if stage != "after-final-create":
                    return
                attempt = next(
                    name for name in os.listdir(root_fd) if name.endswith(".attempt")
                )
                descriptor = os.open(
                    attempt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=root_fd,
                )
                try:
                    os.setxattr(descriptor, "user.gocode.rc0-construction-owner", b"foreign")
                finally:
                    os.close(descriptor)
                raise OSError("injected ownership change")

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout), boundary_hook=tamper
                )
            self.assertTrue(any(path.name.endswith(".attempt") for path in root.iterdir()))
            self.assertFalse((root / f".{SOURCE}.complete").exists())
            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.load_completed_fixture_evidence(root, SOURCE)

    def test_directory_mode_failure_cleans_reserved_namespace(self):
        evidence = evidence_module()
        atomic = __import__("scripts.rc0_candidate.atomic_publish", fromlist=["unused"])
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            lock = root / f".{SOURCE}.construction-lock"
            lock.write_bytes(b"1" * 64 + b"\n"); lock.chmod(0o600)
            with patch.object(atomic.os, "fchmod", side_effect=OSError("injected")):
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout)
                    )
            self.assertFalse((root / SOURCE).exists())

    def test_cleanup_io_error_still_closes_all_descriptors(self):
        evidence = evidence_module()
        atomic = __import__("scripts.rc0_candidate.atomic_publish", fromlist=["unused"])
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            before = set(os.listdir("/proc/self/fd"))

            def fail(stage, _root_fd, _source_sha):
                if stage == "after-blob-fsync":
                    raise OSError("injected construction failure")

            with patch.object(atomic.os, "unlink", side_effect=OSError("injected cleanup failure")):
                try:
                    evidence.build_fixture_evidence(
                        fixture_records(), Path(output), Path(checkout), boundary_hook=fail
                    )
                except evidence.EvidenceConstructionError:
                    pass
                except Exception as error:
                    self.fail(f"cleanup leaked its raw error: {error}")
                else:
                    self.fail("injected construction failure did not fail")
            self.assertEqual(before, set(os.listdir("/proc/self/fd")))


if __name__ == "__main__":
    unittest.main()
