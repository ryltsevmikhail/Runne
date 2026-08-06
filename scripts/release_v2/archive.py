import hashlib
import io
import os
import tarfile
from dataclasses import dataclass
from pathlib import Path

from scripts.release_v2 import archive_fd
from scripts.release_v2.canonical import canonical_json, parse_canonical_json, validate_relative_path, validate_sha256, validate_unique_relative_paths
from scripts.release_v2.inventory import TreeBytes, capture_tree_bytes
from scripts.release_v2.model import ArtifactEntry, FailureCodeV2, ReleaseFailure
from scripts.release_v2.submodule_snapshot import Fd, root_fd


_ARCHIVE_NAME = "archive.tar"
_INDEX_NAME = "archive-index.v1.json"
_FORMAT = "tar-ustar"
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_CYCLE_NAMES = frozenset({_ARCHIVE_NAME, _INDEX_NAME, "release-snapshot.v1.json"})
_OUTPUT_NAMES = frozenset({_ARCHIVE_NAME, _INDEX_NAME})
@dataclass(frozen=True)
class ArchiveIndexV1:
    schema_version: str
    archive_sha256: str
    format: str
    size: int
    candidate_sha256: str
    entries: tuple[ArtifactEntry, ...]

    def __post_init__(self) -> None:
        try:
            if self.schema_version != "release-archive-index-v1" or self.format != _FORMAT or type(self.size) is not int or self.size < 0:
                _invalid()
            validate_sha256(self.archive_sha256)
            validate_sha256(self.candidate_sha256)
            _validate_entries(self.entries)
            if self.candidate_sha256 != _candidate_digest(self.entries):
                _invalid()
        except ReleaseFailure as error:
            if error.code is FailureCodeV2.ARCHIVE_NONDETERMINISTIC:
                raise
            _invalid()
        except Exception:
            _invalid()

    def as_dict(self) -> dict[str, object]:
        return {"archive_sha256": self.archive_sha256, "candidate_sha256": self.candidate_sha256, "entries": [_entry_value(entry) for entry in self.entries], "format": self.format, "schema_version": self.schema_version, "size": self.size}
def build_archive(candidate_root: Path, output: Path, source_date_epoch: int, candidate_sha256: str) -> ArchiveIndexV1:
    try:
        _validate_request(candidate_root, output, source_date_epoch, candidate_sha256)
        with _open_output_directory(output) as parent_fd:
            parent_state = archive_fd.directory_state(parent_fd)
            before = capture_tree_bytes(candidate_root)
            if before.candidate_sha256 != candidate_sha256:
                _invalid()
            _reject_cycles(before.entries)
            with Fd(archive_fd.create_output(parent_fd, _ARCHIVE_NAME)) as archive_fd_value:
                _write_tar(archive_fd_value, before, source_date_epoch)
                archive_fd.sync_fd(archive_fd_value)
                archive_state = archive_fd.state(archive_fd_value)
                archive_raw = archive_fd.read_checked(archive_fd_value)
                archive_fd.require_state(archive_fd_value, archive_state)
                if before != capture_tree_bytes(candidate_root):
                    _invalid()
                index = ArchiveIndexV1("release-archive-index-v1", _sha256(archive_raw), _FORMAT, len(archive_raw), candidate_sha256, before.entries)
                with Fd(archive_fd.create_output(parent_fd, _INDEX_NAME)) as index_fd:
                    _write_bytes(index_fd, canonical_json(index.as_dict()))
                    archive_fd.sync_fd(index_fd)
                    index_state = archive_fd.state(index_fd)
                    index_raw = archive_fd.read_checked(index_fd)
                    archive_fd.require_state(index_fd, index_state)
                    if before != capture_tree_bytes(candidate_root):
                        _invalid()
                    _verify_archive_bytes(archive_raw, index_raw, candidate_sha256, source_date_epoch)
                    archive_fd.sync_fd(archive_fd_value)
                    archive_fd.sync_fd(index_fd)
                    os.fsync(parent_fd)
                    _validate_output(parent_fd, parent_state, archive_fd_value, archive_state, archive_raw, index_fd, index_state, index_raw)
                    if before != capture_tree_bytes(candidate_root) or not _output_path_matches(output, parent_fd):
                        _invalid()
                    return index
    except ReleaseFailure:
        raise
    except Exception:
        _invalid()
def verify_archive_index(archive: Path, index: Path, candidate_sha256: str, source_date_epoch: int) -> ArchiveIndexV1:
    try:
        if type(source_date_epoch) is not int or source_date_epoch < 0:
            _invalid()
        validate_sha256(candidate_sha256)
        if not isinstance(archive, Path) or not isinstance(index, Path) or archive.name != _ARCHIVE_NAME or index.name != _INDEX_NAME or archive.parent != index.parent:
            _invalid()
        with root_fd(archive.parent) as parent_fd:
            parent_state = archive_fd.directory_state(parent_fd)
            with Fd(archive_fd.open_existing(parent_fd, _ARCHIVE_NAME)) as archive_fd_value, Fd(archive_fd.open_existing(parent_fd, _INDEX_NAME)) as index_fd:
                archive_state, index_state = archive_fd.state(archive_fd_value), archive_fd.state(index_fd)
                archive_raw, index_raw = archive_fd.read_checked(archive_fd_value), archive_fd.read_checked(index_fd)
                result = _verify_archive_bytes(archive_raw, index_raw, candidate_sha256, source_date_epoch)
                _validate_output(parent_fd, parent_state, archive_fd_value, archive_state, archive_raw, index_fd, index_state, index_raw)
                return result
    except ReleaseFailure as error:
        if error.code is FailureCodeV2.ARCHIVE_NONDETERMINISTIC:
            raise
        _invalid()
    except Exception:
        _invalid()
def verify_archive_bytes(archive_raw: bytes, index_raw: bytes, candidate_sha256: str, source_date_epoch: int) -> ArchiveIndexV1:
    """Verify detached archive bytes captured by a closed fixture loader."""
    try:
        return _verify_archive_bytes(archive_raw, index_raw, candidate_sha256, source_date_epoch)
    except ReleaseFailure:
        raise
    except Exception:
        _invalid()
def archive_tree_bytes(archive_raw: bytes, index_raw: bytes, candidate_sha256: str, source_date_epoch: int) -> TreeBytes:
    """Return the indexed candidate bytes after validating the detached archive."""
    index = verify_archive_bytes(archive_raw, index_raw, candidate_sha256, source_date_epoch)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_raw), mode="r:") as archive:
            values = tuple((entry.path, archive.extractfile(entry.path).read()) for entry in index.entries if entry.kind == "file")
        return TreeBytes(index.entries, values, index.candidate_sha256)
    except Exception:
        _invalid()
def _validate_output(parent_fd: int, parent_state: tuple[int, int], archive_value: int, archive_state: tuple[int, ...], archive_raw: bytes, index_value: int, index_state: tuple[int, ...], index_raw: bytes) -> None:
    archive_fd.require_state(archive_value, archive_state)
    archive_fd.require_state(index_value, index_state)
    archive_fd.reopen_matches(parent_fd, _ARCHIVE_NAME, archive_state, archive_raw)
    archive_fd.reopen_matches(parent_fd, _INDEX_NAME, index_state, index_raw)
    archive_fd.exact_names(parent_fd, _OUTPUT_NAMES)
    archive_fd.require_state(archive_value, archive_state)
    archive_fd.require_state(index_value, index_state)
    if archive_fd.directory_state(parent_fd) != parent_state:
        _invalid()
def _validate_request(candidate_root: object, output: object, epoch: object, candidate_sha256: object) -> None:
    if not isinstance(candidate_root, Path) or not isinstance(output, Path) or type(epoch) is not int or epoch < 0:
        _invalid()
    validate_sha256(candidate_sha256)
    candidate_path, output_path = os.path.abspath(candidate_root), os.path.abspath(output)
    if os.path.commonpath((candidate_path, output_path)) == candidate_path:
        _invalid()
def _open_output_directory(output: Path) -> Fd:
    descriptor = root_fd(output)
    try:
        if archive_fd.directory_state(descriptor.value) and os.listdir(descriptor.value):
            _invalid()
        return descriptor
    except Exception:
        descriptor.__exit__()
        raise
def _write_tar(descriptor: int, snapshot: TreeBytes, epoch: int) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "wb") as raw, tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for entry in snapshot.entries:
            info = tarfile.TarInfo(entry.path)
            info.mtime, info.uid, info.gid, info.uname, info.gname, info.mode = epoch, 0, 0, "", "", int(entry.mode, 8)
            if entry.kind == "directory":
                info.type, info.size = tarfile.DIRTYPE, 0
                archive.addfile(info)
            else:
                value = snapshot.bytes_for(entry.path)
                info.type, info.size = tarfile.REGTYPE, len(value)
                archive.addfile(info, io.BytesIO(value))
        raw.flush()
def _write_bytes(descriptor: int, value: bytes) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    while value:
        written = os.write(descriptor, value)
        if written <= 0:
            raise OSError("archive write failed")
        value = value[written:]
def _verify_archive_bytes(archive_raw: bytes, index_raw: bytes, candidate_sha256: str, epoch: int) -> ArchiveIndexV1:
    parsed = parse_canonical_json(index_raw, required=frozenset({"schema_version", "archive_sha256", "format", "size", "candidate_sha256", "entries"}), optional=frozenset())
    result = ArchiveIndexV1(_string(parsed, "schema_version"), _string(parsed, "archive_sha256"), _string(parsed, "format"), _integer(parsed, "size"), _string(parsed, "candidate_sha256"), _parse_entries(parsed))
    if result.candidate_sha256 != candidate_sha256 or result.archive_sha256 != _sha256(archive_raw) or result.size != len(archive_raw):
        _invalid()
    _verify_tar(archive_raw, result.entries, epoch)
    return result
def _verify_tar(raw: bytes, entries: tuple[ArtifactEntry, ...], epoch: int) -> None:
    _verify_ustar_layout(raw, entries, epoch)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) != len(entries) or [member.name for member in members] != [entry.path for entry in entries]:
            _invalid()
        for member, entry in zip(members, entries, strict=True):
            validate_relative_path(member.name)
            if member.pax_headers or (member.mtime, member.uid, member.gid, member.uname, member.gname) != (epoch, 0, 0, "", "") or member.mode != int(entry.mode, 8) or member.linkname or member.size != entry.size:
                _invalid()
            if entry.kind == "directory" and (member.type != tarfile.DIRTYPE or member.size != 0):
                _invalid()
            if entry.kind == "file":
                stream = archive.extractfile(member)
                if member.type != tarfile.REGTYPE or stream is None or _sha256(stream.read()) != entry.sha256:
                    _invalid()
def _verify_ustar_layout(raw: bytes, entries: tuple[ArtifactEntry, ...], epoch: int) -> None:
    if not raw or len(raw) % tarfile.RECORDSIZE:
        _invalid()
    offset = 0
    for entry in entries:
        header = raw[offset : offset + 512]
        if len(header) != 512 or header == b"\0" * 512:
            _invalid()
        size = _verify_header(header, entry, epoch)
        data_end, offset = offset + 512 + size, offset + 512 + size + (-size % 512)
        if offset > len(raw) or raw[data_end:offset] != b"\0" * (offset - data_end):
            _invalid()
    if raw[offset : offset + 1024] != b"\0" * 1024:
        _invalid()
    expected = ((offset + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    if len(raw) != expected or raw[offset + 1024 :] != b"\0" * (expected - offset - 1024):
        _invalid()
def _verify_header(header: bytes, entry: ArtifactEntry, epoch: int) -> int:
    if header[257:265] != b"ustar\x0000" or header[157:257] != b"\0" * 100 or header[265:329] != b"\0" * 64 or header[500:] != b"\0" * 12:
        _invalid()
    if header[156:157] != (tarfile.DIRTYPE if entry.kind == "directory" else tarfile.REGTYPE) or _header_path(header) != entry.path + ("/" if entry.kind == "directory" else ""):
        _invalid()
    numeric = (header[100:108], header[108:116], header[116:124], header[124:136], header[136:148])
    if tuple(_canonical_octal(value) for value in numeric) != (int(entry.mode, 8), 0, 0, entry.size, epoch) or header[329:345] != b"\0" * 16:
        _invalid()
    if header[148:156] != f"{sum(header[:148] + b' ' * 8 + header[156:]):06o}\0 ".encode():
        _invalid()
    return entry.size
def _header_path(header: bytes) -> str:
    values = []
    for field in (header[345:500], header[:100]):
        value, separator, padding = field.partition(b"\0")
        if separator and padding.strip(b"\0"):
            _invalid()
        try:
            values.append(value.decode("utf-8"))
        except UnicodeDecodeError:
            _invalid()
    return "/".join(value for value in values if value)
def _canonical_octal(value: bytes) -> int:
    if value[-1:] != b"\0" or not value[:-1] or any(character not in b"01234567" for character in value[:-1]):
        _invalid()
    result = int(value[:-1], 8)
    if value != f"{result:0{len(value) - 1}o}\0".encode():
        _invalid()
    return result
def _parse_entries(parsed: dict[str, object]) -> tuple[ArtifactEntry, ...]:
    raw_entries = parsed["entries"]
    if type(raw_entries) is not list:
        _invalid()
    entries = []
    for raw in raw_entries:
        if type(raw) is not dict or set(raw) != {"path", "kind", "mode", "size", "sha256"}:
            _invalid()
        entries.append(ArtifactEntry(_string(raw, "path"), _string(raw, "kind"), _string(raw, "mode"), _integer(raw, "size"), _string(raw, "sha256")))
    return tuple(entries)
def _validate_entries(entries: object) -> None:
    if type(entries) is not tuple or not all(type(entry) is ArtifactEntry for entry in entries) or entries != tuple(sorted(entries, key=lambda entry: entry.path.encode("utf-8"))):
        _invalid()
    validate_unique_relative_paths(entry.path for entry in entries)
    for entry in entries:
        validate_sha256(entry.sha256)
        if type(entry.size) is not int or entry.size < 0 or entry.kind not in ("file", "directory") or entry.mode not in ("0644", "0755") or (entry.kind == "directory" and (entry.mode != "0755" or entry.size != 0 or entry.sha256 != _EMPTY_SHA256)) or (entry.kind == "file" and entry.path == "checksums.sha256"):
            _invalid()
    _reject_cycles(entries)
def _candidate_digest(entries: tuple[ArtifactEntry, ...]) -> str:
    return _sha256(canonical_json([_entry_value(entry) for entry in entries]))
def _entry_value(entry: ArtifactEntry) -> dict[str, object]:
    return {"kind": entry.kind, "mode": entry.mode, "path": entry.path, "sha256": entry.sha256, "size": entry.size}
def _string(value: dict[str, object], key: str) -> str:
    item = value[key]
    if type(item) is not str:
        _invalid()
    return item
def _integer(value: dict[str, object], key: str) -> int:
    item = value[key]
    if type(item) is not int:
        _invalid()
    return item
def _reject_cycles(entries: tuple[ArtifactEntry, ...]) -> None:
    if any(entry.path.rsplit("/", 1)[-1] in _CYCLE_NAMES for entry in entries):
        _invalid()
def _output_path_matches(output: Path, descriptor: int) -> bool:
    try:
        with root_fd(output) as current:
            return archive_fd.directory_state(descriptor) == archive_fd.directory_state(current)
    except OSError:
        return False
def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
def _invalid() -> None:
    raise ReleaseFailure(FailureCodeV2.ARCHIVE_NONDETERMINISTIC, "archive_nondeterministic")
