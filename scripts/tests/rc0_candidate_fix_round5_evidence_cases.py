import errno
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.tests.test_rc0_candidate_evidence import SOURCE, evidence_module, fixture_records


OWNER_XATTR = "user.gocode.rc0-construction-owner"
ABSENT_XATTR_ERRNO = getattr(errno, "ENODATA", getattr(errno, "ENOATTR", None))


def _attempts(root):
    return tuple(path for path in root.iterdir() if path.name.endswith(".attempt"))


class Rc0CandidateEvidenceFixRound5Tests(unittest.TestCase):
    def test_cleanup_xattr_io_error_fails_closed_without_deleting_attempt(self):
        evidence = evidence_module()
        recovery = __import__("scripts.rc0_candidate.publish_recovery", fromlist=["unused"])
        real_getxattr = recovery.os.getxattr
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def fail_after_open(stage, _root_fd, _source_sha):
                if stage == "after-staging-open":
                    raise OSError("injected construction failure")

            def fail_owner_read(target, name, *args, **kwargs):
                if isinstance(target, int) and name == OWNER_XATTR:
                    raise OSError(errno.EIO, "injected xattr I/O failure")
                return real_getxattr(target, name, *args, **kwargs)

            with patch.object(recovery.os, "getxattr", side_effect=fail_owner_read):
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout), boundary_hook=fail_after_open
                    )
            attempts = _attempts(root)
            self.assertEqual(len(attempts), 1)
            self.assertEqual(tuple(attempts[0].iterdir()), ())

    def test_unbound_empty_cleanup_rechecks_absent_xattr_before_deletion(self):
        self.assertIsNotNone(ABSENT_XATTR_ERRNO)
        evidence = evidence_module()
        recovery = __import__("scripts.rc0_candidate.publish_recovery", fromlist=["unused"])
        real_getxattr = recovery.os.getxattr
        calls = 0
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def fail_after_open(stage, _root_fd, _source_sha):
                if stage == "after-staging-open":
                    raise OSError("injected construction failure")

            def race_owner_xattr(target, name, *args, **kwargs):
                nonlocal calls
                if isinstance(target, int) and name == OWNER_XATTR:
                    calls += 1
                    if calls == 1:
                        raise OSError(ABSENT_XATTR_ERRNO, "no owner xattr")
                    if calls == 2:
                        os.setxattr(target, OWNER_XATTR, b"foreign", flags=os.XATTR_CREATE)
                return real_getxattr(target, name, *args, **kwargs)

            with patch.object(recovery.os, "getxattr", side_effect=race_owner_xattr):
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout), boundary_hook=fail_after_open
                    )
            attempts = _attempts(root)
            self.assertGreaterEqual(calls, 2)
            self.assertEqual(len(attempts), 1)
            self.assertEqual(os.getxattr(attempts[0], OWNER_XATTR), b"foreign")

    def test_lock_creation_boundaries_are_retryable_under_restrictive_umask(self):
        evidence = evidence_module()
        stages = (
            "after-lock-tmpfile-open",
            "after-lock-fchmod",
            "after-lock-fsync",
            "after-lock-link",
            "after-lock-root-fsync",
        )
        linked = {"after-lock-link", "after-lock-root-fsync"}
        for selected in stages:
            with self.subTest(stage=selected), tempfile.TemporaryDirectory() as checkout, \
                    tempfile.TemporaryDirectory() as output:
                root = Path(output)
                lock = root / f".{SOURCE}.construction-lock"

                def fail(stage, _root_fd, _source_sha):
                    if stage == selected:
                        os.umask(previous)
                        raise OSError("injected lock create crash")
                    if stage == "after-lock":
                        os.umask(previous)
                        raise OSError("legacy named-lock create boundary")

                previous = os.umask(0o777)
                try:
                    with self.assertRaises(evidence.EvidenceConstructionError):
                        evidence.build_fixture_evidence(
                            fixture_records(), root, Path(checkout), boundary_hook=fail
                        )
                finally:
                    os.umask(previous)
                self.assertEqual(lock.exists(), selected in linked)
                if lock.exists():
                    self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

                previous = os.umask(0o777)
                try:
                    def restore_after_lock(stage, _root_fd, _source_sha):
                        if stage == "after-lock":
                            os.umask(previous)

                    retry = evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout),
                        boundary_hook=restore_after_lock,
                    )
                finally:
                    os.umask(previous)
                self.assertEqual(retry.directory, root / SOURCE)
                self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    def test_lock_creation_without_unnamed_atomic_link_fails_before_entry_exists(self):
        evidence = evidence_module()
        atomic = __import__("scripts.rc0_candidate.atomic_publish", fromlist=["unused"])
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            with patch.object(atomic, "_LINKAT", None):
                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertFalse((root / f".{SOURCE}.construction-lock").exists())
            self.assertFalse((root / SOURCE).exists())

    def test_builder_prepares_immutable_result_before_publisher(self):
        evidence = evidence_module()
        events = []
        real_digest = evidence.evidence_bundle_digest
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def digest_before_publish(source_sha, blobs):
                self.assertNotIn("publish", events)
                events.append("digest")
                return real_digest(source_sha, blobs)

            def publisher(*_args, **_kwargs):
                events.append("publish")
                return root / "untrusted-publisher-return"

            with patch.object(evidence, "evidence_bundle_digest", digest_before_publish), \
                    patch.object(evidence, "publish_private_blobs", publisher):
                result = evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout)
                )
            self.assertEqual(events, ["digest", "publish"])
            self.assertEqual(result.directory, root / SOURCE)
            with self.assertRaises(TypeError):
                result.blobs["candidate-record.json"] = b"replacement"


if __name__ == "__main__":
    unittest.main()
