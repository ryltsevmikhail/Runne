use super::support;
use runne_application::permission_modes::{FilesystemPermission, NetworkScope};
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;

#[test]
fn partial_profile_closes_an_inheritable_host_file_descriptor_before_exec() {
    eprintln!("RUN: partial_profile_closes_an_inheritable_host_file_descriptor_before_exec");
    let Some(fixture) = support::fixture(NetworkScope::None, [FilesystemPermission::Read], None)
    else {
        return;
    };
    let secret = fixture
        .workspace
        .0
        .parent()
        .unwrap()
        .join(format!("{}-fd-secret", std::process::id()));
    fs::write(&secret, b"host-held").unwrap();
    let file = OpenOptions::new().read(true).open(&secret).unwrap();
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 200) };
    assert!(fd >= 200);
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
        0
    );
    let code = r#"
import errno, os, sys
fd = int(sys.argv[1])
try:
    os.fstat(fd)
except OSError as error:
    assert error.errno == errno.EBADF
else:
    raise AssertionError('inherited descriptor survived the gate')
"#;
    let number = fd.to_string();
    assert_eq!(support::run_python(&fixture, code, &[number.as_str()]), 0);
    unsafe { libc::close(fd) };
    fs::remove_file(secret).unwrap();
    fixture.cleanup();
}
