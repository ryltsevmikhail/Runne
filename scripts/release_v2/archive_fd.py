import os
import stat


_CREATE = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def create_output(parent_fd: int, name: str) -> int:
    return os.open(name, _CREATE, 0o600, dir_fd=parent_fd)


def open_existing(parent_fd: int, name: str) -> int:
    descriptor = os.open(name, _READ, dir_fd=parent_fd)
    try:
        state(descriptor)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def read_checked(descriptor: int) -> bytes:
    before = state(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    values = []
    while value := os.read(descriptor, 1 << 20):
        values.append(value)
    if before != state(descriptor):
        raise ValueError("archive file changed")
    return b"".join(values)


def sync_fd(descriptor: int) -> None:
    os.fsync(descriptor)


def state(descriptor: int) -> tuple[int, ...]:
    value = os.fstat(descriptor)
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise ValueError("archive file is unsafe")
    return _identity(value)


def require_state(descriptor: int, expected: tuple[int, ...]) -> None:
    if state(descriptor) != expected:
        raise ValueError("archive file changed")


def directory_state(descriptor: int) -> tuple[int, int]:
    value = os.fstat(descriptor)
    if not stat.S_ISDIR(value.st_mode):
        raise ValueError("archive parent is unsafe")
    return value.st_dev, value.st_ino


def reopen_matches(parent_fd: int, name: str, original: tuple[int, ...], expected: bytes) -> None:
    descriptor = open_existing(parent_fd, name)
    try:
        observed = state(descriptor)
        if observed[:2] != original[:2] or read_checked(descriptor) != expected or observed != state(descriptor):
            raise ValueError("archive pathname changed")
    finally:
        os.close(descriptor)


def exact_names(parent_fd: int, expected: frozenset[str]) -> None:
    if set(os.listdir(parent_fd)) != expected:
        raise ValueError("archive output names changed")


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns
