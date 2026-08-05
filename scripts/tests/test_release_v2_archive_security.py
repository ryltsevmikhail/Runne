import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.release_v2.archive import build_archive, verify_archive_index
from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.inventory import capture_tree_bytes
from scripts.release_v2.model import FailureCodeV2, ReleaseFailure


class ArchiveSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.candidate = Path(self.temporary.name) / "candidate"
        (self.candidate / "bin").mkdir(parents=True)
        (self.candidate / "README").write_bytes(b"readme\n")
        (self.candidate / "bin" / "gocode").write_bytes(b"launcher\n")
        os.chmod(self.candidate / "README", 0o644)
        os.chmod(self.candidate / "bin", 0o755)
        os.chmod(self.candidate / "bin" / "gocode", 0o755)
        self.candidate_sha256 = capture_tree_bytes(self.candidate).candidate_sha256

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_at_17_recomputed_zero_extent_lengths_block(self) -> None:
        output = self._build_output("zero-extents")
        archive, index = output / "archive.tar", output / "archive-index.v1.json"
        original = archive.read_bytes()
        cases = (("append-block", original + b"\0" * 512), ("append-record", original + b"\0" * tarfile.RECORDSIZE), ("remove-block", original[:-512]), ("remove-record", original[:-tarfile.RECORDSIZE]))
        for name, raw in cases:
            with self.subTest(name=name):
                self._assert_recomputed_archive_blocks(archive, index, raw)

    def test_at_17_recomputed_devmajor_blocks(self) -> None:
        output = self._build_output("devmajor")
        archive, index = output / "archive.tar", output / "archive-index.v1.json"
        raw = bytearray(archive.read_bytes())
        raw[329:337] = b"0000001\0"
        raw[148:156] = b" " * 8
        raw[148:156] = f"{sum(raw[:512]):06o}\0 ".encode()
        self._assert_recomputed_archive_blocks(archive, index, bytes(raw))

    def test_at_17_archive_and_index_fifos_fail_promptly_without_fd_leaks(self) -> None:
        for name in ("archive.tar", "archive-index.v1.json"):
            with self.subTest(name=name):
                output = self._build_output(name)
                target = output / name
                target.unlink()
                os.mkfifo(target)
                before = len(os.listdir("/proc/self/fd"))
                started = time.monotonic()
                result = subprocess.run(self._verify_command(output), cwd=Path.cwd(), timeout=2, check=False)
                self.assertEqual(result.returncode, 0)
                self.assertLess(time.monotonic() - started, 2)
                for _ in range(3):
                    self._assert_code(lambda: verify_archive_index(output / "archive.tar", output / "archive-index.v1.json", self.candidate_sha256, 1_700_000_000))
                self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_pinned_producer_rejects_replaced_output_after_read(self) -> None:
        for name in ("archive.tar", "archive-index.v1.json"):
            with self.subTest(name=name):
                output = Path(self.temporary.name) / f"producer-{name}"
                output.mkdir()
                target, fired = output / name, False
                from scripts.release_v2 import archive_fd

                original = archive_fd.read_checked

                def replace(descriptor: int) -> bytes:
                    nonlocal fired
                    value = original(descriptor)
                    if not fired and target.exists() and os.fstat(descriptor).st_ino == target.stat().st_ino:
                        target.unlink()
                        target.write_bytes(b"replacement\n")
                        fired = True
                    return value

                with patch("scripts.release_v2.archive_fd.read_checked", side_effect=replace):
                    self._assert_code(lambda: build_archive(self.candidate, output, 1_700_000_000, self.candidate_sha256))
                self.assertTrue(fired)

    def test_pinned_verifier_rejects_replaced_output_after_read(self) -> None:
        for name in ("archive.tar", "archive-index.v1.json"):
            with self.subTest(name=name):
                output = self._build_output(f"verifier-{name}")
                target, fired = output / name, False
                from scripts.release_v2 import archive_fd

                original = archive_fd.read_checked

                def replace(descriptor: int) -> bytes:
                    nonlocal fired
                    value = original(descriptor)
                    if not fired and os.fstat(descriptor).st_ino == target.stat().st_ino:
                        target.unlink()
                        target.write_bytes(b"replacement\n")
                        fired = True
                    return value

                with patch("scripts.release_v2.archive_fd.read_checked", side_effect=replace):
                    self._assert_code(lambda: verify_archive_index(output / "archive.tar", output / "archive-index.v1.json", self.candidate_sha256, 1_700_000_000))
                self.assertTrue(fired)

    def test_pinned_descriptors_reject_in_place_mutation(self) -> None:
        output = Path(self.temporary.name) / "in-place"
        output.mkdir()
        from scripts.release_v2 import archive_fd

        original, fired = archive_fd.read_checked, False

        def mutate(descriptor: int) -> bytes:
            nonlocal fired
            value = original(descriptor)
            if not fired:
                os.pwrite(descriptor, b"X", 0)
                fired = True
            return value

        with patch("scripts.release_v2.archive_fd.read_checked", side_effect=mutate):
            self._assert_code(lambda: build_archive(self.candidate, output, 1_700_000_000, self.candidate_sha256))
        self.assertTrue(fired)

    def test_pinned_producer_rejects_extra_hardlink(self) -> None:
        output = Path(self.temporary.name) / "hardlink"
        output.mkdir()
        from scripts.release_v2 import archive_fd

        original, fired = archive_fd.sync_fd, False

        def hardlink(descriptor: int) -> None:
            nonlocal fired
            original(descriptor)
            target = output / "archive.tar"
            if not fired and target.exists():
                os.link(target, output / "attacker-link")
                fired = True

        with patch("scripts.release_v2.archive_fd.sync_fd", side_effect=hardlink):
            self._assert_code(lambda: build_archive(self.candidate, output, 1_700_000_000, self.candidate_sha256))
        self.assertTrue(fired)

    def test_o_excl_collision_is_typed(self) -> None:
        for target_name in ("archive.tar", "archive-index.v1.json"):
            with self.subTest(name=target_name):
                output = Path(self.temporary.name) / f"collision-{target_name}"
                output.mkdir()
                from scripts.release_v2 import archive_fd

                original, fired = archive_fd.create_output, False

                def collide(parent_fd: int, name: str) -> int:
                    nonlocal fired
                    if name == target_name and not fired:
                        os.close(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd))
                        fired = True
                    return original(parent_fd, name)

                with patch("scripts.release_v2.archive_fd.create_output", side_effect=collide):
                    self._assert_code(lambda: build_archive(self.candidate, output, 1_700_000_000, self.candidate_sha256))
                self.assertTrue(fired)

    def test_success_output_has_exactly_archive_and_index(self) -> None:
        output = self._build_output("exact-names")
        self.assertEqual({entry.name for entry in output.iterdir()}, {"archive.tar", "archive-index.v1.json"})

    def _build_output(self, name: str) -> Path:
        output = Path(self.temporary.name) / name
        output.mkdir()
        build_archive(self.candidate, output, 1_700_000_000, self.candidate_sha256)
        return output

    def _assert_recomputed_archive_blocks(self, archive: Path, index: Path, raw: bytes) -> None:
        archive.write_bytes(raw)
        value = json.loads(index.read_text())
        value["archive_sha256"] = hashlib.sha256(raw).hexdigest()
        value["size"] = len(raw)
        index.write_bytes(canonical_json(value))
        self._assert_code(lambda: verify_archive_index(archive, index, self.candidate_sha256, 1_700_000_000))

    def _assert_code(self, call: object) -> None:
        with self.assertRaises(ReleaseFailure) as failure:
            call()
        self.assertIs(failure.exception.code, FailureCodeV2.ARCHIVE_NONDETERMINISTIC)

    def _verify_command(self, output: Path) -> list[str]:
        script = (
            "from pathlib import Path\n"
            "from scripts.release_v2.archive import verify_archive_index\n"
            "from scripts.release_v2.model import FailureCodeV2, ReleaseFailure\n"
            "try:\n"
            f" verify_archive_index(Path({str(output)!r}) / 'archive.tar', Path({str(output)!r}) / 'archive-index.v1.json', {self.candidate_sha256!r}, 1700000000)\n"
            "except ReleaseFailure as error:\n"
            " raise SystemExit(0 if error.code is FailureCodeV2.ARCHIVE_NONDETERMINISTIC else 2)\n"
            "raise SystemExit(3)\n"
        )
        return [sys.executable, "-c", script]


if __name__ == "__main__":
    unittest.main()
