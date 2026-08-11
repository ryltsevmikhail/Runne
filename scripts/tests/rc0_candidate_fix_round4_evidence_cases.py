import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from scripts.tests.test_rc0_candidate_evidence import SOURCE, evidence_module, fixture_records


OWNER_XATTR = "user.gocode.rc0-construction-owner"


def _write(fd, data):
    position = 0
    while position < len(data):
        position += os.write(fd, data[position:])


def _clone_final_at_new_inode(root_fd, source_sha):
    held_name = source_sha + ".held"
    os.rename(source_sha, held_name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
    os.mkdir(source_sha, 0o700, dir_fd=root_fd)
    held_fd = os.open(held_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                      dir_fd=root_fd)
    replacement_fd = os.open(
        source_sha, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
    )
    try:
        os.setxattr(replacement_fd, OWNER_XATTR, os.getxattr(held_fd, OWNER_XATTR))
        for name in os.listdir(held_fd):
            source_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=held_fd)
            try:
                data = os.read(source_fd, os.fstat(source_fd).st_size + 1)
            finally:
                os.close(source_fd)
            target_fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=replacement_fd,
            )
            try:
                _write(target_fd, data)
                os.fsync(target_fd)
            finally:
                os.close(target_fd)
        os.fsync(replacement_fd)
    finally:
        os.close(replacement_fd)
        os.close(held_fd)
    return held_name


def _replace_marker_for_current_blobs(root, source_sha):
    directory = root / source_sha
    owner_id = os.getxattr(directory, OWNER_XATTR)
    metadata = directory.stat()
    blobs = {path.name: path.read_bytes() for path in directory.iterdir()}
    lines = [
        "GOCODE_RC0_COMPLETE_V2",
        f"source_sha={source_sha}",
        f"owner_token={owner_id.decode('ascii')}",
        f"directory_dev={metadata.st_dev}",
        f"directory_ino={metadata.st_ino}",
    ]
    for name in sorted(blobs, key=lambda value: value.encode("ascii")):
        data = blobs[name]
        lines.append(f"{hashlib.sha256(data).hexdigest()} {len(data)} {name}")
    marker = root / f".{source_sha}.complete"
    marker.unlink()
    marker.write_bytes(("\n".join(lines) + "\n").encode("ascii"))
    marker.chmod(0o600)
    os.setxattr(marker, OWNER_XATTR, owner_id)


class Rc0CandidateEvidenceFixRound4Tests(unittest.TestCase):
    def test_builder_rebinds_final_directory_after_each_completion_hook(self):
        evidence = evidence_module()
        for selected in ("after-marker-publish", "after-final-verify"):
            with self.subTest(stage=selected), tempfile.TemporaryDirectory() as checkout, \
                    tempfile.TemporaryDirectory() as output:
                root = Path(output)
                held_names = []

                def swap(stage, root_fd, source_sha):
                    if stage == selected:
                        held_names.append(_clone_final_at_new_inode(root_fd, source_sha))

                with self.assertRaises(evidence.EvidenceConstructionError):
                    evidence.build_fixture_evidence(
                        fixture_records(), root, Path(checkout), boundary_hook=swap
                    )
                self.assertEqual(held_names, [SOURCE + ".held"])
                self.assertTrue((root / SOURCE).is_dir())
                self.assertTrue((root / held_names[0]).is_dir())

    def test_loader_rebinds_final_directory_after_before_return_hook(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))

            def swap(_stage, root_fd, source_sha):
                _clone_final_at_new_inode(root_fd, source_sha)

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.load_completed_fixture_evidence(root, SOURCE, validation_hook=swap)
            self.assertTrue((root / SOURCE).is_dir())
            self.assertTrue((root / (SOURCE + ".held")).is_dir())

    def test_loader_rejects_self_consistent_marker_over_schema_invalid_blobs(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            (root / SOURCE / "candidate-record.json").write_bytes(b"{}")
            (root / SOURCE / "candidate-record.json").chmod(0o600)
            _replace_marker_for_current_blobs(root, SOURCE)
            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.load_completed_fixture_evidence(root, SOURCE)

    def test_cleanup_preserves_owned_directory_with_foreign_blob_replacement(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            changed = []

            def replace_blob(stage, root_fd, _source_sha):
                if stage != "after-blob-fsync" or changed:
                    return
                attempt = next(name for name in os.listdir(root_fd) if name.endswith(".attempt"))
                directory_fd = os.open(
                    attempt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
                )
                try:
                    copied_owner = os.getxattr(directory_fd, OWNER_XATTR)
                    os.setxattr(directory_fd, OWNER_XATTR, copied_owner, flags=os.XATTR_REPLACE)
                    name = next(iter(os.listdir(directory_fd)))
                    os.unlink(name, dir_fd=directory_fd)
                    descriptor = os.open(
                        name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=directory_fd,
                    )
                    try:
                        _write(descriptor, b"foreign replacement bytes")
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    changed.extend((attempt, name))
                finally:
                    os.close(directory_fd)
                raise OSError("injected failure after foreign replacement")

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout), boundary_hook=replace_blob
                )
            attempt, name = changed
            self.assertEqual((root / attempt / name).read_bytes(), b"foreign replacement bytes")
            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertEqual((root / attempt / name).read_bytes(), b"foreign replacement bytes")

    def test_empty_persistent_lock_left_by_create_crash_is_retryable(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            lock = root / f".{SOURCE}.construction-lock"
            descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            result = evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertEqual(result.directory, root / SOURCE)
            self.assertEqual(lock.read_bytes(), b"")

    def test_same_inode_lock_content_rewrite_has_no_authority(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)
            lock_name = f".{SOURCE}.construction-lock"
            identity = []
            sentinel = b"f" * 64 + b"\n"

            def rewrite(stage, root_fd, _source_sha):
                if stage != "after-lock":
                    return
                before = os.stat(lock_name, dir_fd=root_fd, follow_symlinks=False)
                descriptor = os.open(
                    lock_name, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, dir_fd=root_fd
                )
                try:
                    _write(descriptor, sentinel)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                after = os.stat(lock_name, dir_fd=root_fd, follow_symlinks=False)
                identity.extend((before.st_dev, before.st_ino, after.st_dev, after.st_ino))

            first = evidence.build_fixture_evidence(
                fixture_records(), root, Path(checkout), boundary_hook=rewrite
            )
            second = evidence.build_fixture_evidence(fixture_records(), root, Path(checkout))
            self.assertEqual(first.directory, second.directory)
            self.assertEqual(identity[:2], identity[2:])
            self.assertEqual((root / lock_name).read_bytes(), sentinel)

    def test_lock_inode_replacement_after_final_verify_blocks_return(self):
        evidence = evidence_module()
        with tempfile.TemporaryDirectory() as checkout, tempfile.TemporaryDirectory() as output:
            root = Path(output)

            def replace_lock(stage, root_fd, source_sha):
                if stage != "after-final-verify":
                    return
                name = f".{source_sha}.construction-lock"
                os.unlink(name, dir_fd=root_fd)
                descriptor = os.open(
                    name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=root_fd,
                )
                os.close(descriptor)

            with self.assertRaises(evidence.EvidenceConstructionError):
                evidence.build_fixture_evidence(
                    fixture_records(), root, Path(checkout), boundary_hook=replace_lock
                )


if __name__ == "__main__":
    unittest.main()
