use super::{audit_arch, build};
use crate::local_command_linux::{PermissionHelperOperationV1, policy::native_fs_profile};
use std::{
    ffi::CString,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
};

#[test]
fn workspace_helper_filter_denies_external_metadata_but_allows_content_and_rename() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let external = dir.path().join("outside");
    std::fs::write(&external, b"outside").unwrap();
    let before = std::fs::metadata(&external).unwrap();
    let content = workspace.join("content");
    let renamed = workspace.join("renamed");
    let output = std::fs::File::create(&content).unwrap();
    let external = CString::new(external.as_os_str().as_bytes()).unwrap();
    let content_c = CString::new(content.as_os_str().as_bytes()).unwrap();
    let renamed_c = CString::new(renamed.as_os_str().as_bytes()).unwrap();
    let permissions = PermissionHelperOperationV1::Command
        .permissions()
        .iter()
        .copied()
        .collect();
    let mut profile = native_fs_profile(&permissions).unwrap();
    assert!(profile.write_allowed && profile.metadata_allowed && profile.rename_allowed);
    // Exact helper override: content writes do not authorize unmediated metadata syscalls.
    profile.metadata_allowed = false;
    let filter = build(audit_arch().unwrap(), true, true, Some(profile));
    let times = [libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    }; 2];
    let fd = output.as_raw_fd();
    // Only preallocated values and async-signal-safe syscalls are used after fork.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || filter.install() != 0 {
                libc::_exit(10);
            }
            if libc::chmod(external.as_ptr(), 0o000) != -1
                || *libc::__errno_location() != libc::EPERM
            {
                libc::_exit(11);
            }
            if libc::utimensat(libc::AT_FDCWD, external.as_ptr(), times.as_ptr(), 0) != -1
                || *libc::__errno_location() != libc::EPERM
            {
                libc::_exit(12);
            }
            if libc::write(fd, b"new".as_ptr().cast(), 3) != 3 {
                libc::_exit(13);
            }
            if libc::rename(content_c.as_ptr(), renamed_c.as_ptr()) != 0 {
                libc::_exit(14);
            }
            libc::_exit(0);
        }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "native filter regression exit code"
    );
    assert_eq!(std::fs::read(&renamed).unwrap(), b"new");
    let after = std::fs::metadata(dir.path().join("outside")).unwrap();
    assert_eq!(before.mode(), after.mode());
    assert_eq!(
        (before.mtime(), before.mtime_nsec()),
        (after.mtime(), after.mtime_nsec())
    );
}
