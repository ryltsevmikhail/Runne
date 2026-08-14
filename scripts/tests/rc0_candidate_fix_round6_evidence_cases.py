import errno
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.tests.test_rc0_candidate_evidence import SOURCE, evidence_module, fixture_records


OWNER_XATTR = "user.gocode.rc0-construction-owner"


def _attempt(root):
    attempts = tuple(path for path in root.iterdir() if path.name.endswith(".attempt"))
    if len(attempts) != 1:
        raise AssertionError(f"expected one construction attempt, found {len(attempts)}")
    return attempts[0]


def _snapshot(path):
    directory = path.stat()
    blobs = {
        child.name: ((child.stat().st_dev, child.stat().st_ino), child.read_bytes())
        for child in path.iterdir()
    }
    return (directory.st_dev, directory.st_ino), blobs


class Rc0CandidateEvidenceFixRound6Tests(unittest.TestCase):
    def test_populated_cleanup_final_owner_io_error_preserves_every_blob(self):
        evidence = evidence_module()
        recovery = __import__("scripts.rc0_candidate.publish_recovery", fromlist=["unused"])
        real_getxattr = recovery.os.getxattr
        owner_reads = 0
        before = None
        attempt = None
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def fail_after_population(stage, _root_fd, _source_sha):
                nonlocal before, attempt
                if stage == "after-directory-fsync":
                    attempt = _attempt(root)
                    before = _snapshot(attempt)
                    raise OSError("injected construction failure")

            def fail_final_owner_read(target, name, *args, **kwargs):
                nonlocal owner_reads
                if isinstance(target, int) and name == OWNER_XATTR:
                    owner_reads += 1
                    if owner_reads == 3:
                        raise OSError(errno.EIO, "injected final owner read failure")
                return real_getxattr(target, name, *args, **kwargs)

            with patch.object(recovery.os, "getxattr", side_effect=fail_final_owner_read):
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout),
                        boundary_hook=fail_after_population,
                    )
            self.assertEqual(owner_reads, 3)
            self.assertIsNotNone(attempt)
            self.assertTrue(attempt.is_dir())
            self.assertEqual(_snapshot(attempt), before)

    def test_populated_cleanup_final_owner_change_preserves_every_blob(self):
        evidence = evidence_module()
        recovery = __import__("scripts.rc0_candidate.publish_recovery", fromlist=["unused"])
        real_getxattr = recovery.os.getxattr
        owner_reads = 0
        before = None
        attempt = None
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def fail_after_population(stage, _root_fd, _source_sha):
                nonlocal before, attempt
                if stage == "after-directory-fsync":
                    attempt = _attempt(root)
                    before = _snapshot(attempt)
                    raise OSError("injected construction failure")

            def change_owner_on_final_read(target, name, *args, **kwargs):
                nonlocal owner_reads
                if isinstance(target, int) and name == OWNER_XATTR:
                    owner_reads += 1
                    if owner_reads == 3:
                        os.setxattr(
                            target, OWNER_XATTR, b"foreign", flags=os.XATTR_REPLACE
                        )
                return real_getxattr(target, name, *args, **kwargs)

            with patch.object(recovery.os, "getxattr", side_effect=change_owner_on_final_read):
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout),
                        boundary_hook=fail_after_population,
                    )
            self.assertEqual(owner_reads, 3)
            self.assertIsNotNone(attempt)
            self.assertTrue(attempt.is_dir())
            self.assertEqual(_snapshot(attempt), before)
            self.assertEqual(os.getxattr(attempt, OWNER_XATTR), b"foreign")


if __name__ == "__main__":
    unittest.main()
