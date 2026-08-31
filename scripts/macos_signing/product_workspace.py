import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from .product_layout import (
    APP_ZIP_RELATIVE,
    DMG_RELATIVE,
    DMG_ROOT_RELATIVE,
    EVIDENCE_NAME,
    OUTPUT_DMG_NAME,
    WORK_DIRECTORY,
)


@dataclass(frozen=True)
class PublicationTarget:
    root: Path
    directory: Path
    output_dmg: Path
    evidence_path: Path


@dataclass(frozen=True)
class PrivateWorkspace:
    path: Path
    device: int
    inode: int
    dmg_root_device: int
    dmg_root_inode: int


def validate_publication_target(
    root: Path,
    output_dmg: Path,
    evidence_path: Path,
) -> PublicationTarget | None:
    try:
        if not all(isinstance(path, Path) for path in (output_dmg, evidence_path)):
            return None
        requested_directory = output_dmg.parent
        directory = root / requested_directory.name
        if (
            output_dmg.name != OUTPUT_DMG_NAME
            or evidence_path.name != EVIDENCE_NAME
            or evidence_path.parent != requested_directory
            or directory.exists()
            or directory.is_symlink()
            or requested_directory.parent.resolve(strict=True) != root
            or directory.name in ("", ".", "..", WORK_DIRECTORY)
            or (root / WORK_DIRECTORY).exists()
            or (root / WORK_DIRECTORY).is_symlink()
        ):
            return None
        return PublicationTarget(
            root,
            directory,
            directory / OUTPUT_DMG_NAME,
            directory / EVIDENCE_NAME,
        )
    except (OSError, TypeError, ValueError):
        return None


def regular_external_file(path: Path) -> bool:
    try:
        information = path.lstat()
        return (
            path.is_absolute()
            and not path.is_symlink()
            and stat.S_ISREG(information.st_mode)
            and path.resolve(strict=True) == path
        )
    except (OSError, TypeError, ValueError):
        return False


def create_private_workspace(root: Path) -> PrivateWorkspace:
    path = root / WORK_DIRECTORY
    dmg_root = root / DMG_ROOT_RELATIVE
    os.mkdir(path, mode=0o700)
    try:
        os.mkdir(dmg_root, mode=0o700)
        info = path.lstat()
        dmg_info = dmg_root.lstat()
        workspace = PrivateWorkspace(
            path,
            info.st_dev,
            info.st_ino,
            dmg_info.st_dev,
            dmg_info.st_ino,
        )
        if not workspace_is_current(workspace):
            raise OSError("workspace binding changed")
        return workspace
    except Exception:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        raise


def workspace_is_current(workspace: PrivateWorkspace) -> bool:
    try:
        dmg_root = workspace.path.parent / DMG_ROOT_RELATIVE
        dmg_info = dmg_root.lstat()
        return (
            _workspace_root_is_current(workspace)
            and not dmg_root.is_symlink()
            and stat.S_ISDIR(dmg_info.st_mode)
            and (dmg_info.st_dev, dmg_info.st_ino)
            == (workspace.dmg_root_device, workspace.dmg_root_inode)
            and dmg_info.st_uid == os.getuid()
            and stat.S_IMODE(dmg_info.st_mode) & 0o077 == 0
        )
    except (OSError, TypeError, ValueError):
        return False


def publish_workspace(
    workspace: PrivateWorkspace,
    target: PublicationTarget,
    evidence: bytes,
) -> None:
    if not workspace_is_current(workspace):
        raise OSError("workspace binding changed")
    dmg = target.root / DMG_RELATIVE
    archive = target.root / APP_ZIP_RELATIVE
    dmg_root = target.root / DMG_ROOT_RELATIVE
    if not all(_regular_file(path) for path in (dmg, archive)):
        raise OSError("invalid publication artifact")
    evidence_path = workspace.path / EVIDENCE_NAME
    with evidence_path.open("xb") as handle:
        handle.write(evidence)
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_file(dmg)
    archive.unlink()
    if not workspace_is_current(workspace):
        raise OSError("workspace binding changed")
    shutil.rmtree(dmg_root)
    if set(workspace.path.iterdir()) != {dmg, evidence_path}:
        raise OSError("unexpected workspace content")
    _fsync_directory(workspace.path)
    os.replace(workspace.path, target.directory)
    try:
        _fsync_directory(target.root)
    except OSError:
        pass


def cleanup_workspace(workspace: PrivateWorkspace | None) -> None:
    if workspace is not None and _workspace_root_is_current(workspace):
        shutil.rmtree(workspace.path)


def _workspace_root_is_current(workspace: PrivateWorkspace) -> bool:
    try:
        info = workspace.path.lstat()
        return (
            not workspace.path.is_symlink()
            and stat.S_ISDIR(info.st_mode)
            and (info.st_dev, info.st_ino) == (workspace.device, workspace.inode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) & 0o077 == 0
        )
    except (OSError, TypeError, ValueError):
        return False


def _regular_file(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
