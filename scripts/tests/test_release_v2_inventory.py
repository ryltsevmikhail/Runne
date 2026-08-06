import hashlib
import os
import socket
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.release_v2.inventory import (
    build_inventory,
    capture_tree_bytes,
    checksum_rows,
    parse_checksums,
    verify_checksums,
    verify_inventory_unchanged,
)
from scripts.release_v2 import archive as archive_module
from scripts.release_v2.archive import ArchiveIndexV1, build_archive, verify_archive_index
from scripts.release_v2.canonical import canonical_json
from scripts.release_v2.model import ArtifactEntry, ArtifactInventoryV2, FailureCodeV1, FailureCodeV2, ReleaseFailure


def _entry(path: str, kind: str, mode: str, value: bytes = b"") -> ArtifactEntry:
    return ArtifactEntry(path, kind, mode, len(value), hashlib.sha256(value).hexdigest())


def _inventory_digest(candidate_sha256: str, entries: tuple[ArtifactEntry, ...]) -> str:
    values = [
        {"kind": entry.kind, "mode": entry.mode, "path": entry.path, "sha256": entry.sha256, "size": entry.size}
        for entry in entries
    ]
    return hashlib.sha256(canonical_json({"candidate_sha256": candidate_sha256, "entries": values, "schema_version": "artifact-inventory-v2"})).hexdigest()


def _write_tree(root: Path) -> tuple[ArtifactEntry, ...]:
    (root / "bin").mkdir()
    (root / "bin" / "gocode").write_bytes(b"launcher\n")
    (root / "README").write_bytes(b"readme\n")
    os.chmod(root / "bin", 0o755)
    os.chmod(root / "bin" / "gocode", 0o755)
    os.chmod(root / "README", 0o644)
    return (_entry("README", "file", "0644", b"readme\n"), _entry("bin", "directory", "0755"), _entry("bin/gocode", "file", "0755", b"launcher\n"))


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "candidate"
        self.source = Path(self.temporary.name) / "source"
        self.root.mkdir()
        self.source.mkdir()
        self.declared = _write_tree(self.root)
        _write_tree(self.source)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_code(self, code: FailureCodeV1 | FailureCodeV2, call: object) -> None:
        with self.assertRaises(ReleaseFailure) as failure:
            call()
        self.assertIs(failure.exception.code, code)

    def test_at_07_complete_components_are_accepted(self) -> None:
        inventory = build_inventory(self.root, self.declared)
        self.assertEqual(inventory.schema_version, "artifact-inventory-v2")
        self.assertEqual(inventory.entries, tuple(sorted(self.declared, key=lambda entry: entry.path.encode())))
        self.assertEqual(len(inventory.candidate_sha256), 64)

    def test_at_07_missing_extra_duplicate_component_blocks(self) -> None:
        (self.root / "bin" / "gocode").unlink()
        self.assert_code(FailureCodeV1.ARTIFACT_MISSING, lambda: build_inventory(self.root, self.declared))
        (self.root / "bin" / "gocode").write_bytes(b"launcher\n")
        os.chmod(self.root / "bin" / "gocode", 0o755)
        extra = self.root / "extra"
        extra.write_bytes(b"extra\n")
        os.chmod(extra, 0o644)
        self.assert_code(FailureCodeV1.ARTIFACT_UNEXPECTED, lambda: build_inventory(self.root, self.declared))
        self.assert_code(FailureCodeV1.CHECKSUM_INVALID, lambda: build_inventory(self.root, self.declared + (self.declared[0],)))

    def test_at_08_relative_regular_path_is_accepted(self) -> None:
        self.assertEqual(build_inventory(self.root, self.declared).entries[0].path, "README")

    def test_at_08_traversal_absolute_symlink_blocks(self) -> None:
        bad = _entry("../escape", "file", "0644")
        self.assert_code(FailureCodeV1.PATH_UNSAFE, lambda: build_inventory(self.root, (bad,)))
        absolute = _entry("/escape", "file", "0644")
        self.assert_code(FailureCodeV1.PATH_UNSAFE, lambda: build_inventory(self.root, (absolute,)))
        nul = _entry("nul\x00path", "file", "0644")
        self.assert_code(FailureCodeV1.PATH_UNSAFE, lambda: build_inventory(self.root, (nul,)))
        (self.root / "link").symlink_to("README")
        self.assert_code(FailureCodeV1.PATH_UNSAFE, lambda: build_inventory(self.root, self.declared))

    def test_at_09_distinct_portable_paths_are_accepted(self) -> None:
        self.assertEqual(capture_tree_bytes(self.root).entries, build_inventory(self.root, self.declared).entries)

    def test_at_09_casefold_collision_blocks(self) -> None:
        (self.root / "readme").write_bytes(b"other\n")
        declared = self.declared + (_entry("readme", "file", "0644", b"other\n"),)
        self.assert_code(FailureCodeV2.CASE_COLLISION_REJECTED, lambda: build_inventory(self.root, declared))
        nfd = _entry("cafe\u0301", "file", "0644")
        self.assert_code(FailureCodeV1.PATH_UNSAFE, lambda: build_inventory(self.root, self.declared + (nfd,)))

    def test_at_11_matching_artifact_digest_is_accepted(self) -> None:
        self.assertEqual(build_inventory(self.root, self.declared).entries, self.declared)

    def test_at_11_altered_artifact_blocks(self) -> None:
        (self.root / "README").write_bytes(b"altered\n")
        self.assert_code(FailureCodeV1.ARTIFACT_DIGEST_MISMATCH, lambda: build_inventory(self.root, self.declared))

    def test_at_12_declared_artifact_is_present(self) -> None:
        self.assertEqual(len(build_inventory(self.root, self.declared).entries), 3)

    def test_at_12_missing_artifact_blocks(self) -> None:
        (self.root / "README").unlink()
        self.assert_code(FailureCodeV1.ARTIFACT_MISSING, lambda: build_inventory(self.root, self.declared))

    def test_at_13_declared_inventory_has_no_extra_file(self) -> None:
        self.assertFalse(any(entry.path == "extra" for entry in build_inventory(self.root, self.declared).entries))

    def test_at_13_unexpected_artifact_blocks(self) -> None:
        (self.root / "extra").write_bytes(b"extra\n")
        os.chmod(self.root / "extra", 0o644)
        self.assert_code(FailureCodeV1.ARTIFACT_UNEXPECTED, lambda: build_inventory(self.root, self.declared))

    def test_at_14_canonical_checksums_are_accepted(self) -> None:
        inventory = build_inventory(self.root, self.declared)
        rows = checksum_rows(inventory)
        expected = b"".join(f"{entry.sha256}  {entry.path}\n".encode("utf-8") for entry in inventory.entries if entry.kind == "file")
        self.assertEqual(rows, expected)
        self.assertEqual(parse_checksums(rows, inventory), tuple(entry for entry in inventory.entries if entry.kind == "file"))
        verify_checksums(self.root, rows, inventory)

    def test_at_14_malformed_or_duplicate_checksum_blocks(self) -> None:
        inventory = build_inventory(self.root, self.declared)
        rows = checksum_rows(inventory)
        self.assert_code(FailureCodeV1.CHECKSUM_INVALID, lambda: parse_checksums(b"bad\n", inventory))
        self.assert_code(FailureCodeV1.CHECKSUM_INVALID, lambda: parse_checksums(rows + rows.splitlines(True)[0], inventory))
        wrong = ArtifactInventoryV2(inventory.schema_version, "0" * 64, inventory.entries, inventory.inventory_sha256)
        self.assert_code(FailureCodeV1.CHECKSUM_INVALID, lambda: parse_checksums(rows, wrong))
        rebound = ArtifactInventoryV2(inventory.schema_version, "0" * 64, inventory.entries, _inventory_digest("0" * 64, inventory.entries))
        self.assert_code(FailureCodeV1.CHECKSUM_INVALID, lambda: checksum_rows(rebound))
        unsorted = tuple(reversed(inventory.entries))
        noncanonical = ArtifactInventoryV2(inventory.schema_version, inventory.candidate_sha256, unsorted, _inventory_digest(inventory.candidate_sha256, unsorted))
        self.assert_code(FailureCodeV1.CHECKSUM_INVALID, lambda: checksum_rows(noncanonical))
        self.assert_code(FailureCodeV1.CHECKSUM_INVALID, lambda: checksum_rows(build_inventory(self.root, self.declared + (_entry("checksums.sha256", "file", "0644"),))))

    def test_at_15_allowed_executable_mode_is_accepted(self) -> None:
        self.assertEqual(build_inventory(self.root, self.declared).entries[-1].mode, "0755")

    def test_at_15_wrong_executable_mode_blocks(self) -> None:
        os.chmod(self.root / "bin" / "gocode", 0o644)
        self.assert_code(FailureCodeV1.ARTIFACT_MODE_MISMATCH, lambda: build_inventory(self.root, self.declared))

    def test_at_16_readonly_verifier_preserves_bytes(self) -> None:
        source_before, candidate_before = capture_tree_bytes(self.source), capture_tree_bytes(self.root)
        before = (self.source / "README").read_bytes(), (self.root / "README").read_bytes()
        build_inventory(self.root, self.declared)
        verify_inventory_unchanged(source_before, candidate_before, self.source, self.root)
        self.assertEqual(before, ((self.source / "README").read_bytes(), (self.root / "README").read_bytes()))

    def test_at_16_detected_input_mutation_blocks(self) -> None:
        source_before, candidate_before = capture_tree_bytes(self.source), capture_tree_bytes(self.root)
        original = candidate_before.bytes_for("README")
        (self.root / "README").write_bytes(b"changed\n")
        self.assert_code(FailureCodeV1.INPUT_MUTATION_DETECTED, lambda: verify_inventory_unchanged(source_before, candidate_before, self.source, self.root))
        self.assertEqual(original, b"readme\n")

    def test_at_17_two_archives_are_byte_equal(self) -> None:
        source_before, candidate_before = capture_tree_bytes(self.source), capture_tree_bytes(self.root)
        first, second = Path(self.temporary.name) / "first", Path(self.temporary.name) / "second"
        first.mkdir()
        second.mkdir()
        first_index = build_archive(self.root, first, 1_700_000_000, candidate_before.candidate_sha256)
        second_index = build_archive(self.root, second, 1_700_000_000, candidate_before.candidate_sha256)
        first_archive, second_archive = first / "archive.tar", second / "archive.tar"
        self.assertEqual(hashlib.sha256(first_archive.read_bytes()).hexdigest(), hashlib.sha256(second_archive.read_bytes()).hexdigest())
        self.assertEqual((first / "archive-index.v1.json").read_bytes(), (second / "archive-index.v1.json").read_bytes())
        self.assertEqual(first_index, second_index)
        with tarfile.open(first_archive, "r:") as archive:
            self.assertEqual(archive.getnames(), [entry.path for entry in candidate_before.entries])
            for member in archive.getmembers():
                self.assertEqual((member.mtime, member.uid, member.gid, member.uname, member.gname), (1_700_000_000, 0, 0, "", ""))
        verify_archive_index(first_archive, first / "archive-index.v1.json", candidate_before.candidate_sha256, 1_700_000_000)
        verify_inventory_unchanged(source_before, candidate_before, self.source, self.root)

    def test_at_17_nondeterministic_archive_blocks(self) -> None:
        output = Path(self.temporary.name) / "output"
        output.mkdir()
        candidate_sha256 = capture_tree_bytes(self.root).candidate_sha256
        build_archive(self.root, output, 1_700_000_000, candidate_sha256)
        archive, index = output / "archive.tar", output / "archive-index.v1.json"
        archive.write_bytes(archive.read_bytes() + b"changed")
        self.assert_code(FailureCodeV2.ARCHIVE_NONDETERMINISTIC, lambda: verify_archive_index(archive, index, candidate_sha256, 1_700_000_000))
        changed_output = Path(self.temporary.name) / "changed"
        changed_output.mkdir()
        (self.root / "README").write_bytes(b"changed\n")
        self.assert_code(FailureCodeV2.ARCHIVE_NONDETERMINISTIC, lambda: build_archive(self.root, changed_output, 1_700_000_000, candidate_sha256))

    def test_at_17_archive_index_rejects_noncanonical_inventory(self) -> None:
        cases = (
            (_entry("../escape", "file", "0644"),), (_entry("/escape", "file", "0644"),),
            (_entry("README", "file", "0644"), _entry("README", "file", "0644")),
            (_entry("README", "file", "0644"), _entry("readme", "file", "0644")),
            (_entry("pipe", "fifo", "0644"),), (_entry("unsafe", "file", "0600"),),
        )
        for entries in cases:
            with self.subTest(entries=entries):
                self.assert_code(FailureCodeV2.ARCHIVE_NONDETERMINISTIC, lambda: ArchiveIndexV1("release-archive-index-v1", "0" * 64, "tar-ustar", 0, "0" * 64, entries))

    def test_at_17_recomputed_wrong_candidate_blocks(self) -> None:
        output = Path(self.temporary.name) / "output"
        output.mkdir()
        built = build_archive(self.root, output, 1_700_000_000, capture_tree_bytes(self.root).candidate_sha256)
        altered = built.as_dict()
        altered["candidate_sha256"] = "0" * 64
        (output / "archive-index.v1.json").write_bytes(canonical_json(altered))
        self.assert_code(FailureCodeV2.ARCHIVE_NONDETERMINISTIC, lambda: verify_archive_index(output / "archive.tar", output / "archive-index.v1.json", "0" * 64, 1_700_000_000))

    def test_at_17_mtime_and_non_ustar_block(self) -> None:
        output = Path(self.temporary.name) / "output"
        output.mkdir()
        candidate = capture_tree_bytes(self.root).candidate_sha256
        built = build_archive(self.root, output, 1_700_000_000, candidate)
        archive, index = output / "archive.tar", output / "archive-index.v1.json"
        original = archive.read_bytes()
        for offset, value in ((136, f"{1_700_000_001:011o}\0".encode()), (257, b"ustar  \0")):
            raw = bytearray(original)
            raw[offset : offset + len(value)] = value
            raw[148:156] = b" " * 8
            raw[148:156] = f"{sum(raw[:512]):06o}\0 ".encode()
            archive.write_bytes(raw)
            tampered = built.as_dict()
            tampered["archive_sha256"] = hashlib.sha256(raw).hexdigest()
            index.write_bytes(canonical_json(tampered))
            self.assert_code(FailureCodeV2.ARCHIVE_NONDETERMINISTIC, lambda: verify_archive_index(archive, index, candidate, 1_700_000_000))

    def test_at_17_output_directory_swap_blocks_without_external_write(self) -> None:
        output, moved, attacker = (Path(self.temporary.name) / name for name in ("output", "moved", "attacker"))
        output.mkdir()
        attacker.mkdir()
        original = archive_module._open_output_directory

        def swap(path: Path) -> object:
            descriptor = original(path)
            output.rename(moved)
            output.symlink_to(attacker, target_is_directory=True)
            return descriptor

        with patch("scripts.release_v2.archive._open_output_directory", side_effect=swap):
            self.assert_code(FailureCodeV2.ARCHIVE_NONDETERMINISTIC, lambda: build_archive(self.root, output, 1_700_000_000, capture_tree_bytes(self.root).candidate_sha256))
        self.assertEqual(tuple(attacker.iterdir()), ())

    def test_special_files_and_hardlinks_block(self) -> None:
        os.link(self.root / "README", self.root / "copy")
        self.assert_code(FailureCodeV2.HARDLINK_REJECTED, lambda: capture_tree_bytes(self.root))
        (self.root / "copy").unlink()
        os.mkfifo(self.root / "pipe")
        self.assert_code(FailureCodeV2.SPECIAL_FILE_REJECTED, lambda: capture_tree_bytes(self.root))
        (self.root / "pipe").unlink()
        listener = socket.socket(socket.AF_UNIX)
        try:
            listener.bind(str(self.root / "socket"))
            self.assert_code(FailureCodeV2.SPECIAL_FILE_REJECTED, lambda: capture_tree_bytes(self.root))
        finally:
            listener.close()
        (self.root / "device").write_bytes(b"device\n")
        original_stat = os.stat

        def device_stat(name: object, *args: object, **kwargs: object) -> os.stat_result | SimpleNamespace:
            if name == "device" and kwargs.get("dir_fd") is not None:
                return SimpleNamespace(st_mode=stat.S_IFCHR | 0o644, st_nlink=1)
            return original_stat(name, *args, **kwargs)

        with patch("scripts.release_v2.inventory.os.stat", side_effect=device_stat):
            self.assert_code(FailureCodeV2.SPECIAL_FILE_REJECTED, lambda: capture_tree_bytes(self.root))


if __name__ == "__main__":
    unittest.main()
