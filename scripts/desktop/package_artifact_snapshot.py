"""Descriptor-validated, private snapshots of Desktop package artifacts."""
from __future__ import annotations

import errno
import os
import stat
import tempfile
from pathlib import Path

try:
    from .snapshot_lease import SnapshotLeaseState, SnapshotUseLease
except ImportError:
    from snapshot_lease import SnapshotLeaseState, SnapshotUseLease


class ArtifactAdmissionError(Exception):
    """A fail-closed package admission error with a stable blocker code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ArtifactSnapshot:
    """A read-only, private staged artifact that is safe to hash or execute."""

    def __init__(self, directory: tempfile.TemporaryDirectory[str], path: Path, root_fd: int):
        self._directory = directory
        self._root = Path(directory.name)
        self._root_fd = root_fd
        self._lease_state = SnapshotLeaseState()
        self._closed = False
        self.path = Path(f"/dev/fd/{root_fd}/{path.name}")

    def acquire_use(self) -> SnapshotUseLease:
        return self._lease_state.acquire(self)

    def close(self) -> None:
        if not self._lease_state.begin_close():
            return
        self._closed = True
        try:
            _clear_directory(self._root_fd)
        except OSError:
            pass
        finally:
            try:
                self._directory._finalizer.detach()
                os.close(self._root_fd)
            finally:
                self._lease_state.finish_close()

    @property
    def staging_root(self) -> Path:
        """Raw staging path for cleanup diagnostics; never use it to consume bytes."""
        return self._root


def _unsafe() -> ArtifactAdmissionError:
    return ArtifactAdmissionError("PACKAGE_ARTIFACT_PATH_UNSAFE")


def _require_primitives() -> None:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if os.name != "posix" or not Path("/dev/fd").is_dir() or os.open not in os.supports_dir_fd or any(not hasattr(os, flag) for flag in required):
        raise _unsafe()


def _components(relative_path: str | None) -> tuple[str, ...]:
    if not isinstance(relative_path, str):
        raise ArtifactAdmissionError("PACKAGE_ARTIFACT_PATH_UNRESOLVED")
    path = Path(relative_path)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise _unsafe()
    return path.parts


def _open_root(root: Path) -> int:
    try:
        if stat.S_ISLNK(root.lstat().st_mode):
            raise _unsafe()
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError as error:
        raise ArtifactAdmissionError("PACKAGE_ARTIFACT_MISSING") from error
    except ArtifactAdmissionError:
        raise
    except OSError as error:
        raise _unsafe() from error


def _open_artifact(root_fd: int, parts: tuple[str, ...], bundle: str) -> int:
    parent_fd = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if bundle == "app":
            flags |= os.O_DIRECTORY
        artifact_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
    except FileNotFoundError as error:
        raise ArtifactAdmissionError("PACKAGE_ARTIFACT_MISSING") from error
    except OSError as error:
        raise _unsafe() from error
    finally:
        os.close(parent_fd)
    try:
        mode = os.fstat(artifact_fd).st_mode
    except OSError as error:
        try:
            os.close(artifact_fd)
        finally:
            raise _unsafe() from error
    valid = stat.S_ISDIR(mode) if bundle == "app" else stat.S_ISREG(mode)
    if not valid:
        os.close(artifact_fd)
        raise ArtifactAdmissionError("PACKAGE_ARTIFACT_TYPE_INVALID")
    return artifact_fd


def _open_stage_fd(parent_fd: int, name: str) -> int:
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)


def _open_stage_root(parent_fd: int, name: str, expected: tuple[int, int]) -> int:
    try:
        root_fd = _open_stage_fd(parent_fd, name)
        actual = os.fstat(root_fd)
        if not stat.S_ISDIR(actual.st_mode) or (actual.st_dev, actual.st_ino) != expected:
            os.close(root_fd)
            raise _unsafe()
        return root_fd
    except ArtifactAdmissionError:
        raise
    except OSError as error:
        raise _unsafe() from error


def _copy_file(source_fd: int, destination: Path, mode: int) -> None:
    destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        while chunk := os.read(source_fd, 1024 * 1024):
            while chunk:
                written = os.write(destination_fd, chunk)
                if written == 0:
                    raise OSError(errno.EIO, "package snapshot write failed")
                chunk = chunk[written:]
    finally:
        os.close(destination_fd)
    destination.chmod(0o500 if mode & stat.S_IXUSR else 0o400)


def _copy_directory(source_fd: int, destination: Path) -> None:
    try:
        names = os.listdir(source_fd)
    except OSError as error:
        raise _unsafe() from error
    for name in names:
        try:
            entry = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError as error:
            raise _unsafe() from error
        if stat.S_ISLNK(entry.st_mode):
            raise _unsafe()
        target = destination / name
        if stat.S_ISDIR(entry.st_mode):
            target.mkdir(mode=0o700)
            try:
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd)
            except OSError as error:
                raise _unsafe() from error
            try:
                if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                    raise _unsafe()
                _copy_directory(child_fd, target)
            finally:
                os.close(child_fd)
            target.chmod(0o500)
        elif stat.S_ISREG(entry.st_mode):
            try:
                child_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_fd)
            except OSError as error:
                raise _unsafe() from error
            try:
                if not stat.S_ISREG(os.fstat(child_fd).st_mode):
                    raise _unsafe()
                _copy_file(child_fd, target, entry.st_mode)
            finally:
                os.close(child_fd)
        else:
            raise _unsafe()


def _clear_directory(directory_fd: int) -> None:
    os.fchmod(directory_fd, 0o700)
    for name in os.listdir(directory_fd):
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(entry.st_mode):
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                _clear_directory(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)


def _discard_stage(stage: tempfile.TemporaryDirectory[str], root_fd: int) -> None:
    try:
        _clear_directory(root_fd)
    except OSError:
        pass
    finally:
        stage._finalizer.detach()
        os.close(root_fd)


def _stage_from_artifact_fd(artifact_fd: int, bundle: str) -> ArtifactSnapshot:
    stage: tempfile.TemporaryDirectory[str] | None = None
    parent_fd: int | None = None
    stage_root_fd: int | None = None
    try:
        stage = tempfile.TemporaryDirectory(prefix="runne-package-")
        stage_path = Path(stage.name)
        stage_stat = stage_path.lstat()
        if not stat.S_ISDIR(stage_stat.st_mode):
            raise _unsafe()
        parent_fd = os.open(stage_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stage_root_fd = _open_stage_root(parent_fd, stage_path.name, (stage_stat.st_dev, stage_stat.st_ino))
        os.close(parent_fd)
        parent_fd = None
        destination = Path(f"/dev/fd/{stage_root_fd}") / ("artifact.app" if bundle == "app" else "artifact")
        if bundle == "app":
            destination.mkdir(mode=0o700)
            _copy_directory(artifact_fd, destination)
            destination.chmod(0o500)
        else:
            _copy_file(artifact_fd, destination, os.fstat(artifact_fd).st_mode)
        os.fchmod(stage_root_fd, 0o500)
        snapshot = ArtifactSnapshot(stage, destination, stage_root_fd)
        stage_root_fd = None
        return snapshot
    except ArtifactAdmissionError:
        if stage_root_fd is not None:
            _discard_stage(stage, stage_root_fd)
            stage_root_fd = None
        elif stage is not None:
            stage._finalizer.detach()
        raise
    except OSError as error:
        if stage_root_fd is not None:
            _discard_stage(stage, stage_root_fd)
            stage_root_fd = None
        elif stage is not None:
            stage._finalizer.detach()
        code = "PACKAGE_ARTIFACT_MISSING" if error.errno == errno.ENOENT else "PACKAGE_ARTIFACT_PATH_UNSAFE"
        raise ArtifactAdmissionError(code) from error
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if stage_root_fd is not None:
            os.close(stage_root_fd)
        os.close(artifact_fd)


def _stage_artifact_posix(root: Path, relative_path: str | None, bundle: str) -> ArtifactSnapshot:
    """Copy a no-follow admitted artifact into a private read-only snapshot."""
    _require_primitives()
    source_root_fd = _open_root(root)
    try:
        artifact_fd = _open_artifact(source_root_fd, _components(relative_path), bundle)
    finally:
        os.close(source_root_fd)
    return _stage_from_artifact_fd(artifact_fd, bundle)


def _windows_stage_artifact(root: Path, relative_path: str | None, bundle: str) -> object:
    try:
        from .windows_package_snapshot import stage_artifact
    except ImportError as error:
        raise _unsafe() from error
    try:
        return stage_artifact(root, relative_path, bundle)
    except Exception as error:
        code = getattr(error, "code", None)
        if isinstance(code, str):
            raise ArtifactAdmissionError(code) from error
        raise _unsafe() from error


def stage_artifact(root: Path, relative_path: str | None, bundle: str) -> object:
    """Admit through a platform-specific descriptor/handle-pinned adapter."""
    return _windows_stage_artifact(root, relative_path, bundle) if os.name == "nt" else _stage_artifact_posix(root, relative_path, bundle)
