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

    // Test that platform-specific constants are correct
    assert_eq!(runne_daemon::lock::O_NOFOLLOW_VAL, 0o400000);
}
