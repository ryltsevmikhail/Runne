"""Windows handle-pinned package snapshot adapter."""
from __future__ import annotations

import ctypes
import hashlib
import os
import tempfile
from ctypes import wintypes
from pathlib import Path
try:
    from .windows_package_cleanup import CLEANUP_UNSAFE, WindowsSnapshotCleanupError, clear_stage, is_pinned_snapshot_path, register, unregister
    from .snapshot_lease import SnapshotLeaseState, SnapshotUseLease
except ImportError:
    from windows_package_cleanup import CLEANUP_UNSAFE, WindowsSnapshotCleanupError, clear_stage, is_pinned_snapshot_path, register, unregister
    from snapshot_lease import SnapshotLeaseState, SnapshotUseLease
class WindowsSnapshotError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
_UNSAFE = "PACKAGE_ARTIFACT_PATH_UNSAFE"
_INVALID_TYPE = "PACKAGE_ARTIFACT_TYPE_INVALID"
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_READ_ATTRIBUTES = 0x80
_DELETE = 0x10000
_SYNCHRONIZE = 0x00100000
_FILE_SHARE_READ = 1
_OPEN_EXISTING = 3
_FILE_OPEN = 1
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_FLAG_OPEN_REPARSE_POINT = 0x200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x2000000
_FILE_SYNCHRONOUS_IO_NONALERT = 0x20
_FILE_DIRECTORY_FILE = 1
_FILE_NON_DIRECTORY_FILE = 0x40
_OBJ_CASE_INSENSITIVE = 0x40
_NO_MORE_FILES = 0x80000006
_INVALID_HANDLE = ctypes.c_void_p(-1).value
class _FileInformation(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME), ("access", wintypes.FILETIME), ("write", wintypes.FILETIME), ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD), ("size_low", wintypes.DWORD), ("links", wintypes.DWORD), ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]
class _UnicodeString(ctypes.Structure):
    _fields_ = [("length", wintypes.USHORT), ("maximum", wintypes.USHORT), ("buffer", wintypes.LPWSTR)]
class _ObjectAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.ULONG), ("root", ctypes.c_void_p), ("name", ctypes.POINTER(_UnicodeString)), ("attributes", wintypes.ULONG), ("security", ctypes.c_void_p), ("quality", ctypes.c_void_p)]
class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]
def _api() -> object:
    if os.name != "nt":
        raise WindowsSnapshotError(_UNSAFE)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.POINTER(_FileInformation)]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel32.WriteFile.restype = wintypes.BOOL
    return kernel32
def _nt_api() -> object:
    if os.name != "nt":
        raise WindowsSnapshotError("WINDOWS_RELATIVE_PRIMITIVE_UNAVAILABLE")
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtCreateFile.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.ULONG, ctypes.POINTER(_ObjectAttributes), ctypes.POINTER(_IoStatusBlock), ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG]
    ntdll.NtCreateFile.restype = ctypes.c_long
    ntdll.NtQueryDirectoryFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(_IoStatusBlock), ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG, wintypes.BOOLEAN, wintypes.LPCWSTR, wintypes.BOOLEAN]
    ntdll.NtQueryDirectoryFile.restype = ctypes.c_long
    return ntdll
def _identity(kernel32: object, handle: int, directory: bool) -> tuple[int, int, int]:
    info = _FileInformation()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)) or info.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise WindowsSnapshotError(_UNSAFE)
    if bool(info.attributes & _FILE_ATTRIBUTE_DIRECTORY) != directory:
        raise WindowsSnapshotError(_INVALID_TYPE)
    return info.volume, info.index_high, info.index_low
def _same_identity(left: tuple[int, int, int], right: tuple[int, int, int]) -> bool:
    """Compare the complete Windows identity, including the low index word."""
    return left == right
def _open_path(path: Path, directory: bool, delete: bool = False) -> tuple[int, tuple[int, int, int]]:
    kernel32 = _api()
    flags = _FILE_FLAG_OPEN_REPARSE_POINT | (_FILE_FLAG_BACKUP_SEMANTICS if directory else 0)
    access = _GENERIC_READ | (_DELETE if delete else 0)
    handle = kernel32.CreateFileW(str(path), access, _FILE_SHARE_READ, None, _OPEN_EXISTING, flags, None)
    if handle in (None, _INVALID_HANDLE):
        raise WindowsSnapshotError(_UNSAFE)
    try:
        return int(handle), _identity(kernel32, handle, directory)
    except Exception:
        kernel32.CloseHandle(handle)
        raise
def _open_child_relative(parent_handle: int, name: str, directory: bool, delete: bool = False) -> tuple[int, tuple[int, int, int]]:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise WindowsSnapshotError(_UNSAFE)
    ntdll = _nt_api()
    name_buffer = ctypes.create_unicode_buffer(name)
    name_value = _UnicodeString(len(name) * 2, (len(name) + 1) * 2, ctypes.cast(name_buffer, wintypes.LPWSTR))
    attributes = _ObjectAttributes(ctypes.sizeof(_ObjectAttributes), ctypes.c_void_p(parent_handle), ctypes.byref(name_value), _OBJ_CASE_INSENSITIVE, None, None)
    io_status = _IoStatusBlock()
    handle = ctypes.c_void_p()
    options = _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_SYNCHRONOUS_IO_NONALERT | (_FILE_DIRECTORY_FILE if directory else _FILE_NON_DIRECTORY_FILE)
    access = _GENERIC_READ | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE | (_DELETE if delete else 0)
    status = ntdll.NtCreateFile(ctypes.byref(handle), access, ctypes.byref(attributes), ctypes.byref(io_status), None, _FILE_ATTRIBUTE_NORMAL, _FILE_SHARE_READ, _FILE_OPEN, options, None, 0)
    if status != 0 or not handle.value:
        raise WindowsSnapshotError("WINDOWS_RELATIVE_PRIMITIVE_UNAVAILABLE" if status else _UNSAFE)
    try:
        return int(handle.value), _identity(_api(), handle, directory)
    except Exception:
        _api().CloseHandle(handle)
        raise
def _enumerate_children(source_handle: int) -> list[tuple[str, bool]]:
    """Enumerate only through the retained source directory handle."""
    ntdll = _nt_api()
    result: list[tuple[str, bool]] = []
    restart = True
    while True:
        buffer = ctypes.create_string_buffer(64 * 1024)
        io_status = _IoStatusBlock()
        status = ntdll.NtQueryDirectoryFile(source_handle, None, None, None, ctypes.byref(io_status), buffer, len(buffer), 1, False, None, restart)
        unsigned = status & 0xFFFFFFFF
        if unsigned == _NO_MORE_FILES:
            return result
        if status != 0:
            raise WindowsSnapshotError("WINDOWS_RELATIVE_PRIMITIVE_UNAVAILABLE")
        offset = 0
        while True:
            next_offset = int.from_bytes(buffer.raw[offset:offset + 4], "little")
            name_length = int.from_bytes(buffer.raw[offset + 60:offset + 64], "little")
            attributes = int.from_bytes(buffer.raw[offset + 56:offset + 60], "little")
            name = buffer.raw[offset + 64:offset + 64 + name_length].decode("utf-16-le")
            if name not in {".", ".."}:
                if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                    raise WindowsSnapshotError(_UNSAFE)
                result.append((name, bool(attributes & _FILE_ATTRIBUTE_DIRECTORY)))
            if not next_offset:
                break
            offset += next_offset
        restart = False
def _close(handle: int) -> None:
    _api().CloseHandle(handle)


def _parts(relative_path: str | None) -> tuple[str, ...]:
    if not isinstance(relative_path, str):
        raise WindowsSnapshotError("PACKAGE_ARTIFACT_PATH_UNRESOLVED")
    path = Path(relative_path)
    if path.is_absolute() or not path.parts or ".." in path.parts or "\\" in relative_path:
        raise WindowsSnapshotError(_UNSAFE)
    return path.parts
def _read_write(source: int, destination: Path) -> None:
    kernel32 = _api()
    target = kernel32.CreateFileW(str(destination), _GENERIC_WRITE, _FILE_SHARE_READ, None, 1, _FILE_ATTRIBUTE_NORMAL, None)
    if target in (None, _INVALID_HANDLE):
        raise WindowsSnapshotError(_UNSAFE)
    try:
        while True:
            buffer = ctypes.create_string_buffer(1024 * 1024)
            count = wintypes.DWORD()
            if not kernel32.ReadFile(source, buffer, len(buffer), ctypes.byref(count), None):
                raise WindowsSnapshotError(_UNSAFE)
            if not count.value:
                break
            written = wintypes.DWORD()
            if not kernel32.WriteFile(target, buffer, count.value, ctypes.byref(written), None) or written.value != count.value:
                raise WindowsSnapshotError(_UNSAFE)
    finally:
        kernel32.CloseHandle(target)
def _copy_tree(destination: Path, source_handle: int, handles: list[int]) -> None:
    destination.mkdir()
    destination_handle, _ = _open_path(destination, True)
    handles.append(destination_handle)
    for name, child_directory in _enumerate_children(source_handle):
        child_handle, _ = _open_child_relative(source_handle, name, child_directory)
        handles.append(child_handle)
        target = destination / name
        if child_directory:
            _copy_tree(target, child_handle, handles)
        else:
            _read_write(child_handle, target)


class WindowsSnapshot:
    def __init__(self, path: Path, stage_root: Path, stage_identity: tuple[int, int, int], stage_handle: int, handles: list[int], artifact_handle: int, artifact_identity: tuple[int, int, int], bundle: str):
        self.path = path
        self.staging_root = stage_root
        self._stage_identity = stage_identity
        self._stage_root_handle = stage_handle
        self._handles = handles
        self._artifact_handle = artifact_handle
        self._artifact_identity = artifact_identity
        self._lease_state = SnapshotLeaseState()
        self._bundle = bundle
        self._closed = False

    def acquire_use(self) -> SnapshotUseLease:
        return self._lease_state.acquire(self)

    def close(self) -> None:
        if not self._lease_state.begin_close():
            return
        self._closed = True
        for handle in reversed(self._handles):
            if handle != self._stage_root_handle:
                try:
                    _close(handle)
                except OSError:
                    pass
        cleanup_error = None
        try:
            clear_stage(self._stage_root_handle, _enumerate_children, _open_child_relative, _close)
        except WindowsSnapshotCleanupError as error:
            cleanup_error = error
        finally:
            try:
                _close(self._stage_root_handle)
            finally:
                try:
                    unregister(self.path, self)
                finally:
                    self._lease_state.finish_close()
        if cleanup_error is not None:
            raise cleanup_error

    def sha256(self) -> str:
        if self._bundle == "app":
            raise WindowsSnapshotError("WINDOWS_NATIVE_PATH_UNPINNED")
        kernel32 = _api()
        data = bytearray()
        buffer = ctypes.create_string_buffer(1024 * 1024)
        while True:
            count = wintypes.DWORD()
            if not kernel32.ReadFile(self._artifact_handle, buffer, len(buffer), ctypes.byref(count), None):
                raise WindowsSnapshotError(_UNSAFE)
            if not count.value:
                break
            data.extend(buffer.raw[:count.value])
        return hashlib.sha256(data).hexdigest()


def stage_artifact(root: Path, relative_path: str | None, bundle: str) -> WindowsSnapshot:
    parts = _parts(relative_path)
    expected_directory = bundle == "app"
    handles: list[int] = []
    stage_root: Path | None = None
    stage_identity: tuple[int, int, int] | None = None
    stage_root_handle: int | None = None
    try:
        root_handle, _ = _open_path(root, True)
        handles.append(root_handle)
        source_handle = root_handle
        for index, part in enumerate(parts):
            source_handle, _ = _open_child_relative(source_handle, part, index < len(parts) - 1 or expected_directory)
            handles.append(source_handle)
        stage_root = Path(tempfile.mkdtemp(prefix="runne-package-"))
        stage_root_handle, stage_identity = _open_path(stage_root, True, True)
        if not _same_identity(stage_identity, _identity(_api(), stage_root_handle, True)):
            raise WindowsSnapshotError(_UNSAFE)
        handles.append(stage_root_handle)
        artifact = stage_root / ("artifact.app" if expected_directory else "artifact")
        if expected_directory:
            _copy_tree(artifact, source_handle, handles)
            artifact_handle, artifact_identity = _open_child_relative(stage_root_handle, artifact.name, True)
        else:
            _read_write(source_handle, artifact)
            artifact_handle, artifact_identity = _open_child_relative(stage_root_handle, artifact.name, False)
        handles.append(artifact_handle)
        snapshot = WindowsSnapshot(artifact, stage_root, stage_identity, stage_root_handle, handles, artifact_handle, artifact_identity, bundle)
        register(snapshot.path, snapshot, artifact_identity)
        return snapshot
    except Exception:
        cleanup_error = None
        for handle in reversed(handles):
            if handle != stage_root_handle:
                try:
                    _close(handle)
                except OSError:
                    pass
        if stage_root_handle is not None:
            try:
                clear_stage(stage_root_handle, _enumerate_children, _open_child_relative, _close)
            except WindowsSnapshotCleanupError as error:
                cleanup_error = error
            finally:
                _close(stage_root_handle)
        elif stage_root is not None:
            cleanup_error = WindowsSnapshotCleanupError(CLEANUP_UNSAFE)
        if cleanup_error is not None:
            raise cleanup_error
        raise
