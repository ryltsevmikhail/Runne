//! Landlock enforcement test: escape-path blocking.

use super::super::{add_landlock_path_rule, create_landlock_ruleset, restrict_self_with_landlock};

#[test]
fn landlock_restrict_self_blocks_escape_path() {
    // Этот тест доказывает, что Landlock может запретить доступ за пределы
    // разрешённого каталога. Тест выполняется в forked child,
    // чтобы не замораживать родительский процесс.
    use std::ffi::CString;
    use std::fs;

    const ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const ACCESS_FS_READ_DIR: u64 = 1 << 3;

    let tmp = std::env::temp_dir().join("gocode_landlock_enforcement_test");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create temp dir");
    let allowed_file = tmp.join("allowed.txt");
    fs::write(&allowed_file, "ok").expect("write allowed file");

    let dir_cstr = CString::new(tmp.as_os_str().as_encoded_bytes()).expect("temp dir path");
    let allowed_cstr =
        CString::new(allowed_file.as_os_str().as_encoded_bytes()).expect("allowed file path");

    let dir_fd = unsafe {
        libc::open(
            dir_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    assert!(dir_fd >= 0, "failed to open temp dir");

    let ruleset_fd =
        create_landlock_ruleset(ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR).expect("create ruleset");
    add_landlock_path_rule(ruleset_fd, dir_fd, ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR)
        .expect("add path rule");
    unsafe { libc::close(dir_fd) };

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        // Child: apply sandbox, then verify escape is blocked and allowed path works.
        restrict_self_with_landlock(ruleset_fd).expect("restrict_self");
        unsafe { libc::close(ruleset_fd) };

        // /etc/passwd must be blocked with EACCES.
        let etc_fd = unsafe {
            libc::open(
                "/etc/passwd\0".as_ptr() as *const libc::c_char,
                libc::O_RDONLY,
            )
        };
        if etc_fd >= 0 {
            unsafe { libc::close(etc_fd) };
            eprintln!("escape path was not blocked");
            unsafe { libc::exit(1) };
        }
        let errno = unsafe { *libc::__errno_location() };
        if errno != libc::EACCES {
            eprintln!("unexpected errno for blocked path: {errno}");
            unsafe { libc::exit(2) };
        }

        // Allowed file must remain readable.
        let fd = unsafe { libc::open(allowed_cstr.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            eprintln!("allowed path was unexpectedly blocked");
            unsafe { libc::exit(3) };
        }
        let mut buf = [0u8; 4];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        unsafe { libc::close(fd) };
        if n != 2 || &buf[..2] != b"ok" {
            eprintln!("allowed file content mismatch");
            unsafe { libc::exit(4) };
        }

        unsafe { libc::exit(0) };
    }

    // Parent: wait for child and verify it reported success.
    unsafe { libc::close(ruleset_fd) };
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "waitpid failed");
    assert!(libc::WIFEXITED(status), "child did not exit cleanly");
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "child failed to verify Landlock containment"
    );
}
