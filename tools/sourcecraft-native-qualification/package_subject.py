"""Descriptor-bound package measurements shared by controller and verifier."""
from __future__ import annotations

import hashlib
import os
import stat

from codec import Rejected
from contract import CANARY, ROLE_PATHS

MACHO_ARM64 = b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01"


def open_package(path: str) -> int:
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise Rejected("protected package is unavailable") from None


def subject(descriptor: int, protected: bool = False) -> dict[str, object]:
    root = os.fstat(descriptor)
    if not stat.S_ISDIR(root.st_mode) or root.st_nlink < 2:
        raise Rejected("protected package root is invalid")
    files: dict[str, dict[str, int | str]] = {}
    _walk(descriptor, "", files, protected)
    roles = {}
    for role, name in ROLE_PATHS.items():
        item = files.get(name)
        if item is None or item["architecture"] != "arm64":
            raise Rejected("package role is not a Mach-O executable")
        roles[role] = item
    return {"root_device":root.st_dev,"root_inode":root.st_ino,"files":files,"roles":roles}


def signed_subject(value: dict[str, object]) -> dict[str, object]:
    """Portable receipt: exact content/measurements without host-specific inode IDs."""
    files = canonical_files(value)
    roles = canonical_roles(value, files)
    return {"files":files,"roles":roles}


def snapshot(value: dict[str, object]) -> dict[str, str]:
    """Portable content-only package snapshot shared by controller and verifier."""
    return {name:item["sha256"] for name,item in canonical_files(value).items()}


def canonical_files(value: dict[str, object]) -> dict[str, dict[str, int | str]]:
    files = value.get("files")
    if not isinstance(files, dict): raise Rejected("package subject is invalid")
    keys = ("sha256","size","macho_magic","architecture","canary_matches")
    try: return {name:{key:item[key] for key in keys} for name,item in files.items()}
    except (AttributeError, KeyError): raise Rejected("package subject is invalid") from None


def canonical_roles(value: dict[str, object], files: dict[str, dict[str, int | str]] | None = None) -> dict[str, dict[str, int | str]]:
    files = canonical_files(value) if files is None else files
    try: return {name:files[ROLE_PATHS[name]] for name in ROLE_PATHS}
    except KeyError: raise Rejected("package role is not a Mach-O executable") from None


def _walk(parent: int, prefix: str, result: dict[str, dict[str, int | str]], protected: bool) -> None:
    try:
        for name in os.listdir(parent):
            if name in {".", ".."} or "/" in name: raise Rejected("package inventory is invalid")
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if protected and (info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise Rejected("package component is mutable")
            relative = f"{prefix}/{name}" if prefix else name
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try: _walk(child, relative, result, protected)
                finally: os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
                try: result[relative] = _file_subject(child)
                finally: os.close(child)
            else: raise Rejected("package inventory is invalid")
    except OSError:
        raise Rejected("package inventory is unavailable") from None


def _file_subject(descriptor: int) -> dict[str, int | str]:
    info = os.fstat(descriptor)
    if info.st_size < 0 or info.st_size > 2**31: raise Rejected("package file is invalid")
    needle = CANARY.encode("ascii"); digest = hashlib.sha256(); header = os.read(descriptor, 8); digest.update(header)
    matches, tail = 0, header[-(len(needle) - 1):]
    while block := os.read(descriptor, 65536):
        content = tail + block; matches += content.count(needle); tail = content[-(len(needle) - 1):]; digest.update(block)
    return {"device":info.st_dev,"inode":info.st_ino,"size":info.st_size,
            "sha256":digest.hexdigest(),"macho_magic":header[:4].hex(),
            "architecture":"arm64" if header == MACHO_ARM64 else "unsupported","canary_matches":matches}
