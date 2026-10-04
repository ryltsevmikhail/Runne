use super::*;
use runne_platform::local_command_linux::{
    LinuxCommandExecutable, LinuxCommandSpec, SealedExecutableSnapshot,
};
use std::os::fd::AsRawFd;

#[test]
fn executes_the_same_sealed_memfd_bytes_used_for_approval() {
    let Some((_root, area, _identity)) = run_or_skip() else {
        return;
    };
    eprintln!("RUN: executes_the_same_sealed_memfd_bytes_used_for_approval");
    let workspace = Workspace::new();
    let workspace_fd = workspace.file();
    let cwd = workspace.cwd();
    let source_path = workspace.0.join("approved-shell-copy");
    std::fs::copy("/bin/sh", &source_path).expect("copy shell fixture");
    let source = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&source_path)
        .expect("open shell fixture");
    unsafe { libc::fchmod(source.as_raw_fd(), 0o700) };
    let snapshot = SealedExecutableSnapshot::from_held_file(&source)
        .expect("create sealed executable snapshot");
    // Mutate the same inode after approval snapshot creation; exec must still
    // consume the sealed bytes that were hashed, not the mutable source file.
    assert_eq!(
        unsafe { libc::pwrite(source.as_raw_fd(), [0u8].as_ptr().cast(), 1, 0) },
        1
    );
    let marker = workspace.0.join("memfd-executed");
    let command = LinuxCommandSpec {
        executable: LinuxCommandExecutable::SealedSnapshot(&snapshot),
        workspace: &workspace_fd,
        cwd: &cwd,
        argv: vec![
            OsString::from("approved-shell-copy"),
            OsString::from("-c"),
            OsString::from(format!("printf sealed > '{}'", marker.display())),
        ],
        env: Vec::new(),
    };
    if let Err(error) = command.preflight() {
        assert!(
            !marker.exists(),
            "unsupported sealed memfd must be refused before code"
        );
        assert!(!area.is_populated().expect("area remains empty"));
        panic!("sealed memfd preflight failed: {error:?}");
    }
    let mut child = command.spawn_gated(&area).expect("prepare memfd gate");
    child.release().expect("release memfd gate");
    assert_eq!(child.wait(Duration::from_secs(10)).expect("leader exit"), 0);
    assert_eq!(std::fs::read(&marker).expect("command marker"), b"sealed");
    assert!(!area.is_populated().expect("empty managed area"));
    area.remove();
}
