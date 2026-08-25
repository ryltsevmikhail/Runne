"""Handle-relative Windows snapshot cleanup and live-path registry."""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path


CLEANUP_UNSAFE = "WINDOWS_SNAPSHOT_CLEANUP_UNSAFE"
_DELETE = 0x10000
_FILE_DISPOSITION_INFORMATION = 13


class WindowsSnapshotCleanupError(Exception):
    def __init__(self, code: str = CLEANUP_UNSAFE):
        super().__init__(code)
        self.code = code


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("status", ctypes.c_void_p), ("information", ctypes.c_size_t)]


class _FileDisposition(ctypes.Structure):
    _fields_ = [("delete", wintypes.BOOLEAN)]


_live_paths: dict[str, tuple[object, tuple[int, int, int]]] = {}


def register(path: Path, snapshot: object, identity: tuple[int, int, int]) -> None:
    _live_paths[str(path)] = (snapshot, identity)


def unregister(path: Path, snapshot: object) -> None:
    if _live_paths.get(str(path), (None,))[0] is snapshot:
        _live_paths.pop(str(path), None)


def is_pinned_snapshot_path(path: str | Path) -> bool:
    if os.name != "nt":
        return False
    entry = _live_paths.get(str(path))
    if entry is None:
        return False
    snapshot, identity = entry
    return not getattr(snapshot, "_closed", True) and getattr(snapshot, "_artifact_identity", None) == identity


def _api() -> object:
    if os.name != "nt":
        raise WindowsSnapshotCleanupError()
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtSetInformationFile.argtypes = [ctypes.c_void_p, ctypes.POINTER(_IoStatusBlock), ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
    ntdll.NtSetInformationFile.restype = ctypes.c_long
    return ntdll


def _delete_handle(handle: int) -> None:
    status_block = _IoStatusBlock()
    disposition = _FileDisposition(True)
    status = _api().NtSetInformationFile(handle, ctypes.byref(status_block), ctypes.byref(disposition), ctypes.sizeof(disposition), _FILE_DISPOSITION_INFORMATION)
    if status != 0:
        raise WindowsSnapshotCleanupError()


def clear_stage(root_handle: int, enumerate_children: object, open_child_relative: object, close: object, delete_root: bool = True) -> None:
    """Delete the staged tree through the retained root handle only."""
    try:
        for name, directory in enumerate_children(root_handle):
            child, _ = open_child_relative(root_handle, name, directory, True)
            try:
                if directory:
                    clear_stage(child, enumerate_children, open_child_relative, close)
                else:
                    _delete_handle(child)
            finally:
                close(child)
    except WindowsSnapshotCleanupError:
        raise
    except Exception as error:
        raise WindowsSnapshotCleanupError() from error
    if delete_root:
        _delete_handle(root_handle)
