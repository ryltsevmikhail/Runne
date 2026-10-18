use super::support;
use runne_application::permission_modes::{FilesystemPermission, NetworkScope};
use runne_application::project_trust::ManagedEffectClass;
use std::fs;

#[test]
fn write_deny_blocks_content_truncation_shared_mapping_and_metadata_syscalls() {
    eprintln!("RUN: write_deny_blocks_content_truncation_shared_mapping_and_metadata_syscalls");
    let Some(fixture) = support::fixture(
        NetworkScope::None,
        [FilesystemPermission::Read],
        Some(ManagedEffectClass::FsWrite),
    ) else {
        return;
    };
    let existing = fixture.workspace.0.join("read-only");
    fs::write(&existing, b"unchanged").unwrap();
    let code = r#"
import ctypes, errno, mmap, os, sys
path = sys.argv[1]
def denied(call):
    try: call()
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES, errno.EBADF), error.errno
        return
    raise AssertionError('write unexpectedly succeeded')
denied(lambda: os.open(path, os.O_WRONLY))
denied(lambda: os.open(path, os.O_WRONLY | os.O_TRUNC))
denied(lambda: os.truncate(path, 0))
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
fd = os.open(path, os.O_RDONLY)
denied(lambda: os.pwrite(fd, b'x', 0))
try:
    os.ftruncate(fd, 0)
except OSError as error:
    assert error.errno in (errno.EPERM, errno.EACCES, errno.EBADF, errno.EINVAL), error.errno
else:
    raise AssertionError('ftruncate unexpectedly succeeded')
ctypes.set_errno(0)
result = libc.syscall(ctypes.c_long(int(sys.argv[2])), ctypes.c_long(fd), ctypes.c_long(0), ctypes.c_long(0), ctypes.c_long(1))
assert result < 0 and ctypes.get_errno() in (errno.EPERM, errno.EACCES), ctypes.get_errno()
denied(lambda: mmap.mmap(fd, 1, flags=mmap.MAP_SHARED, prot=mmap.PROT_WRITE))
for number in map(int, sys.argv[3:]):
    ctypes.set_errno(0)
    result = libc.syscall(ctypes.c_long(number), *([ctypes.c_long(0)] * 6))
    assert result < 0 and ctypes.get_errno() == errno.EPERM, (number, ctypes.get_errno())
os.close(fd)
"#;
    let metadata = [
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchmodat2,
        libc::SYS_chown,
        libc::SYS_fchown,
        libc::SYS_lchown,
        libc::SYS_fchownat,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
        libc::SYS_utimensat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        libc::SYS_fallocate,
    ];
    let numbers = metadata
        .iter()
        .map(|number| number.to_string())
        .collect::<Vec<_>>();
    let fallocate = libc::SYS_fallocate.to_string();
    let mut args = vec![existing.to_str().unwrap(), fallocate.as_str()];
    args.extend(numbers.iter().map(String::as_str));
    assert_eq!(support::run_python(&fixture, code, &args), 0);
    assert_eq!(fs::read(existing).unwrap(), b"unchanged");
    fixture.cleanup();
}
