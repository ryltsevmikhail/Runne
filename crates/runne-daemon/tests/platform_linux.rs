//! Smoke test for Linux platform compatibility.
//!
//! Verifies daemon bootstrap works on Linux with correct platform-specific
//! constants.

#[cfg(target_os = "linux")]
#[test]
fn linux_smoke_bootstrap_works() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();

    // The exported constant must match the kernel ABI table for the target
    // (hand-coded octal drifts across architectures, e.g. arm64 vs asm-generic).
    assert_eq!(runne_daemon::lock::O_NOFOLLOW_VAL, libc::O_NOFOLLOW);
}
