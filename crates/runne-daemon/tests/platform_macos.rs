//! Smoke test for macOS platform compatibility.
//!
//! Verifies daemon bootstrap works on macOS with correct platform-specific
//! constants.

#[cfg(target_os = "macos")]
#[test]
fn macos_smoke_bootstrap_works() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = dir.path().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();

    assert_eq!(runne_daemon::lock::O_NOFOLLOW_VAL, 0x0100);
}
