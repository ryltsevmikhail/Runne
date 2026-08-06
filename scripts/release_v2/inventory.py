import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from scripts.release_v2.canonical import canonical_json, parse_canonical_json, validate_relative_path, validate_sha256, validate_unique_relative_paths
from scripts.release_v2.model import ArtifactEntry, ArtifactInventoryV2, FailureCodeV1, FailureCodeV2, ReleaseFailure
from scripts.release_v2.submodule_snapshot import directory_fd, file_fd, root_fd


_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class TreeBytes:
    entries: tuple[ArtifactEntry, ...]
    values: tuple[tuple[str, bytes], ...]
    candidate_sha256: str

    def bytes_for(self, path: str) -> bytes:
        for name, value in self.values:
            if name == path:
                return value
        raise KeyError(path)


def capture_tree_bytes(root: Path) -> TreeBytes:
    try:
        with root_fd(root) as descriptor:
            entries, values = _walk(descriptor, "")
        entries.sort(key=lambda entry: entry.path.encode("utf-8"))
        values.sort(key=lambda value: value[0].encode("utf-8"))
        validate_unique_relative_paths(entry.path for entry in entries)
        return TreeBytes(tuple(entries), tuple(values), _candidate_digest(tuple(entries)))
    except ReleaseFailure:
        raise
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.PATH_UNSAFE, "artifact_tree_invalid") from error


def build_inventory(candidate_root: Path, declared: tuple[ArtifactEntry, ...]) -> ArtifactInventoryV2:
    _validate_declared(declared)
    before = capture_tree_bytes(candidate_root)
    _require_exact_entries(before.entries, declared)
    after = capture_tree_bytes(candidate_root)
    if before != after:
        _mutated()
    digest = _inventory_digest(before.candidate_sha256, before.entries)
    return ArtifactInventoryV2("artifact-inventory-v2", before.candidate_sha256, before.entries, digest)


def checksum_rows(inventory: ArtifactInventoryV2) -> bytes:
    _validate_inventory(inventory)
    files = tuple(entry for entry in inventory.entries if entry.kind == "file")
    return b"".join(f"{entry.sha256}  {entry.path}\n".encode("utf-8") for entry in files)


def parse_inventory(raw: bytes) -> ArtifactInventoryV2:
    """Parse one canonical serialized inventory without reopening its source."""
    try:
        document = parse_canonical_json(raw, required=frozenset(("candidate_sha256", "entries", "inventory_sha256", "schema_version")), optional=frozenset())
        rows = document["entries"]
        if type(rows) is not list:
            _checksum_invalid()
        entries = tuple(_parse_entry(row) for row in rows)
        return ArtifactInventoryV2(document["schema_version"], document["candidate_sha256"], entries, document["inventory_sha256"])
    except ReleaseFailure:
        raise
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.CHECKSUM_INVALID, "inventory_parse_invalid") from error


def _parse_entry(row: object) -> ArtifactEntry:
    if type(row) is not dict or frozenset(row) != frozenset(("kind", "mode", "path", "sha256", "size")):
        _checksum_invalid()
    return ArtifactEntry(row["path"], row["kind"], row["mode"], row["size"], row["sha256"])


def parse_checksums(raw: bytes, inventory: ArtifactInventoryV2) -> tuple[ArtifactEntry, ...]:
    _validate_inventory(inventory)
    if type(raw) is not bytes or not raw or not raw.endswith(b"\n"):
        _checksum_invalid()
    expected = tuple(entry for entry in inventory.entries if entry.kind == "file")
    by_path = {entry.path: entry for entry in expected}
    values: list[ArtifactEntry] = []
    for row in raw.splitlines():
        if len(row) < 67 or row[64:66] != b"  ":
            _checksum_invalid()
        try:
            digest, path = row[:64].decode("ascii"), row[66:].decode("utf-8", "strict")
            validate_sha256(digest)
            validate_relative_path(path)
        except ReleaseFailure as error:
            raise ReleaseFailure(FailureCodeV1.CHECKSUM_INVALID, "checksum_row_invalid") from error
        entry = by_path.get(path)
        if entry is None:
            _checksum_invalid()
        values.append(ArtifactEntry(path, "file", entry.mode, entry.size, digest))
    parsed = tuple(sorted(values, key=lambda entry: entry.path.encode("utf-8")))
    if len(parsed) != len(values) or parsed != expected or raw != checksum_rows(inventory):
        _checksum_invalid()
    return parsed


def verify_checksums(candidate_root: Path, raw: bytes, inventory: ArtifactInventoryV2) -> None:
    _validate_inventory(inventory)
    if capture_tree_bytes(candidate_root).candidate_sha256 != inventory.candidate_sha256:
        _checksum_invalid()
    if build_inventory(candidate_root, inventory.entries).inventory_sha256 != inventory.inventory_sha256:
        _checksum_invalid()
    parse_checksums(raw, inventory)


def verify_inventory_unchanged(source_before: TreeBytes, candidate_before: TreeBytes, source_root: Path, candidate_root: Path) -> None:
    if type(source_before) is not TreeBytes or type(candidate_before) is not TreeBytes:
        _checksum_invalid()
    try:
        source_after = capture_tree_bytes(source_root)
        candidate_after = capture_tree_bytes(candidate_root)
    except ReleaseFailure as error:
        raise ReleaseFailure(FailureCodeV1.INPUT_MUTATION_DETECTED, "artifact_tree_changed") from error
    if source_before != source_after or candidate_before != candidate_after:
        _mutated()


def _walk(parent_fd: int, prefix: str) -> tuple[list[ArtifactEntry], list[tuple[str, bytes]]]:
    entries: list[ArtifactEntry] = []
    values: list[tuple[str, bytes]] = []
    for name in os.listdir(parent_fd):
        path = validate_relative_path(f"{prefix}/{name}" if prefix else name)
        initial = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(initial.st_mode):
            raise ReleaseFailure(FailureCodeV1.PATH_UNSAFE, "artifact_symlink_rejected")
        if stat.S_ISDIR(initial.st_mode):
            if stat.S_IMODE(initial.st_mode) != 0o755:
                _mode_invalid()
            with directory_fd(parent_fd, name) as descriptor:
                opened = os.fstat(descriptor)
                if not stat.S_ISDIR(opened.st_mode) or _state(initial) != _state(opened):
                    _mutated()
                children, child_values = _walk(descriptor, path)
                if _state(opened) != _state(os.fstat(descriptor)):
                    _mutated()
            entries.append(ArtifactEntry(path, "directory", "0755", 0, _EMPTY_SHA256))
            entries.extend(children)
            values.extend(child_values)
        elif stat.S_ISREG(initial.st_mode):
            entries.append(_read_file(parent_fd, name, path, initial, values))
        elif initial.st_nlink > 1:
            _hardlink()
        else:
            _special()
    return entries, values


def _read_file(parent_fd: int, name: str, path: str, initial: os.stat_result, values: list[tuple[str, bytes]]) -> ArtifactEntry:
    with file_fd(parent_fd, name) as descriptor:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or _state(initial) != _state(before):
            _mutated()
        if before.st_nlink != 1:
            _hardlink()
        mode = stat.S_IMODE(before.st_mode)
        if mode not in (0o644, 0o755):
            _mode_invalid()
        value = _read_fd(descriptor)
        if _state(before) != _state(os.fstat(descriptor)):
            _mutated()
    values.append((path, value))
    return ArtifactEntry(path, "file", f"{mode:04o}", len(value), hashlib.sha256(value).hexdigest())


def _validate_declared(declared: object) -> None:
    if type(declared) is not tuple or not all(type(entry) is ArtifactEntry for entry in declared):
        _checksum_invalid()
    paths = tuple(entry.path for entry in declared)
    if len(set(paths)) != len(paths):
        _checksum_invalid()
    try:
        validate_unique_relative_paths(paths)
        for entry in declared:
            validate_sha256(entry.sha256)
            if type(entry.size) is not int or entry.size < 0 or entry.kind not in ("file", "directory") or entry.mode not in ("0644", "0755"):
                _checksum_invalid()
            if (entry.kind == "directory" and (entry.mode != "0755" or entry.size != 0 or entry.sha256 != _EMPTY_SHA256)) or (entry.kind == "file" and entry.path == "checksums.sha256"):
                _checksum_invalid()
    except ReleaseFailure:
        raise
    except Exception as error:
        raise ReleaseFailure(FailureCodeV1.CHECKSUM_INVALID, "artifact_declaration_invalid") from error
def _require_exact_entries(actual: tuple[ArtifactEntry, ...], declared: tuple[ArtifactEntry, ...]) -> None:
    values = {entry.path: entry for entry in actual}
    expected = {entry.path: entry for entry in declared}
    if set(values) - set(expected):
        raise ReleaseFailure(FailureCodeV1.ARTIFACT_UNEXPECTED, "artifact_unexpected")
    if set(expected) - set(values):
        raise ReleaseFailure(FailureCodeV1.ARTIFACT_MISSING, "artifact_missing")
    for path, entry in expected.items():
        current = values[path]
        if current.kind != entry.kind or current.size != entry.size or current.sha256 != entry.sha256:
            raise ReleaseFailure(FailureCodeV1.ARTIFACT_DIGEST_MISMATCH, "artifact_digest_mismatch")
        if current.mode != entry.mode:
            _mode_invalid()


def _validate_inventory(inventory: object) -> None:
    if type(inventory) is not ArtifactInventoryV2 or inventory.schema_version != "artifact-inventory-v2":
        _checksum_invalid()
    _validate_declared(inventory.entries)
    if inventory.entries != tuple(sorted(inventory.entries, key=lambda entry: entry.path.encode("utf-8"))):
        _checksum_invalid()
    try:
        validate_sha256(inventory.candidate_sha256)
        validate_sha256(inventory.inventory_sha256)
    except ReleaseFailure as error:
        raise ReleaseFailure(FailureCodeV1.CHECKSUM_INVALID, "inventory_digest_invalid") from error
    if inventory.candidate_sha256 != _candidate_digest(inventory.entries):
        _checksum_invalid()
    if inventory.inventory_sha256 != _inventory_digest(inventory.candidate_sha256, inventory.entries):
        _checksum_invalid()


def _candidate_digest(entries: tuple[ArtifactEntry, ...]) -> str:
    return hashlib.sha256(canonical_json([_entry_value(entry) for entry in entries])).hexdigest()


def _inventory_digest(candidate_sha256: str, entries: tuple[ArtifactEntry, ...]) -> str:
    return hashlib.sha256(canonical_json({"candidate_sha256": candidate_sha256, "entries": [_entry_value(entry) for entry in entries], "schema_version": "artifact-inventory-v2"})).hexdigest()


def _entry_value(entry: ArtifactEntry) -> dict[str, object]:
    return {"kind": entry.kind, "mode": entry.mode, "path": entry.path, "sha256": entry.sha256, "size": entry.size}


def _read_fd(descriptor: int) -> bytes:
    values = []
    while value := os.read(descriptor, 1 << 20):
        values.append(value)
    return b"".join(values)


def _state(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _checksum_invalid() -> None:
    raise ReleaseFailure(FailureCodeV1.CHECKSUM_INVALID, "checksum_invalid")


def _mode_invalid() -> None:
    raise ReleaseFailure(FailureCodeV1.ARTIFACT_MODE_MISMATCH, "artifact_mode_invalid")


def _hardlink() -> None:
    raise ReleaseFailure(FailureCodeV2.HARDLINK_REJECTED, "artifact_hardlink_rejected")


def _special() -> None:
    raise ReleaseFailure(FailureCodeV2.SPECIAL_FILE_REJECTED, "artifact_special_rejected")


def _mutated() -> None:
    raise ReleaseFailure(FailureCodeV1.INPUT_MUTATION_DETECTED, "artifact_tree_changed")
