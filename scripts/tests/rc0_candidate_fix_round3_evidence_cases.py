import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.tests.test_rc0_candidate_evidence import SOURCE, evidence_module, fixture_records


class Rc0CandidateEvidenceFixRound3Tests(unittest.TestCase):
    def test_renameat2_unavailable_fails_closed_without_final(self):
        evidence = evidence_module()
        atomic = __import__("scripts.rc0_candidate.atomic_publish", fromlist=["unused"])
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            with patch.object(atomic, "_RENAMEAT2", None):
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout)
                    )
            self.assertFalse((root / SOURCE).exists())

    def test_open_xattr_and_rename_crash_boundaries_are_recoverable(self):
        evidence = evidence_module()
        stages = ("after-staging-open", "after-staging-xattr", "after-staging-rename")
        for selected in stages:
            with self.subTest(stage=selected), tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
                root = Path(output)

                def fail(stage, _root_fd, _source_sha):
                    if stage == selected:
                        raise OSError("injected crash boundary")

                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout), boundary_hook=fail
                    )
                result = evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout)
                )
                self.assertEqual(result.directory, root / SOURCE)

    def test_failure_after_staging_mkdir_is_recoverable(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def fail(stage, _root_fd, _source_sha):
                if stage == "after-staging-mkdir":
                    raise OSError("crash after mkdir")

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout), boundary_hook=fail
                )
            result = evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertEqual(result.directory, root / SOURCE)

    def test_marker_link_failure_is_tracked_and_retry_is_safe(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def fail(stage, _root_fd, _source_sha):
                if stage == "after-marker-link":
                    raise OSError("crash before marker stat")

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout), boundary_hook=fail
                )
            retry = evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertEqual(
                set(evidence.load_completed_fixture_evidence(root, SOURCE)),
                set(retry.blobs),
            )

    def test_staging_path_swap_cannot_be_published_or_deleted(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            foreign_name = []

            def swap(stage, root_fd, _source_sha):
                if stage != "before-staging-rename":
                    return
                attempt = next(name for name in os.listdir(root_fd) if name.endswith(".attempt"))
                os.rename(attempt, attempt + ".owned", src_dir_fd=root_fd, dst_dir_fd=root_fd)
                os.mkdir(attempt, 0o700, dir_fd=root_fd)
                attempt_fd = os.open(
                    attempt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
                )
                fd = os.open("foreign", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                             dir_fd=attempt_fd)
                os.write(fd, b"foreign"); os.close(fd); os.close(attempt_fd)
                foreign_name.append(attempt)

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout), boundary_hook=swap
                )
            self.assertFalse((root / SOURCE).exists())
            self.assertEqual((root / foreign_name[0] / "foreign").read_bytes(), b"foreign")
            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertTrue((root / foreign_name[0]).is_dir())

    def test_output_root_path_replacement_never_returns_success(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "output"; root.mkdir(mode=0o700)
            moved = Path(parent) / "output-owned"

            def replace(stage, _root_fd, _source_sha):
                if stage == "before-staging-rename":
                    root.rename(moved)
                    root.mkdir(mode=0o700)

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout), boundary_hook=replace
                )
            self.assertFalse((root / SOURCE).exists())

    def test_post_rename_failure_is_idempotently_recovered(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def fail(stage, _root_fd, _source_sha):
                if stage == "after-final-verify":
                    raise OSError("crash after verified rename")

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout), boundary_hook=fail
                )
            retry = evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertEqual(retry.directory, root / SOURCE)
            again = evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertEqual(again.directory, retry.directory)

    def test_cleanup_error_leaves_owned_attempt_recoverable_with_stable_token(self):
        evidence = evidence_module()
        atomic = __import__("scripts.rc0_candidate.atomic_publish", fromlist=["unused"])
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def fail(stage, _root_fd, _source_sha):
                if stage == "after-blob-fsync":
                    raise OSError("construction failure")

            with patch.object(atomic.os, "unlink", side_effect=OSError("cleanup failure")):
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout), boundary_hook=fail
                    )
            lock = root / f".{SOURCE}.construction-lock"
            token = lock.read_bytes()
            result = evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertEqual(lock.read_bytes(), token)
            self.assertEqual(result.directory, root / SOURCE)

    def test_loader_rechecks_configured_root_path_before_return(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "output"; root.mkdir(mode=0o700)
            evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            moved = Path(parent) / "output-owned"

            def replace(_stage, _root_fd, _source_sha):
                root.rename(moved)
                root.mkdir(mode=0o700)

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.load_completed_fixture_evidence(root, SOURCE, validation_hook=replace)


if __name__ == "__main__":
    unittest.main()
