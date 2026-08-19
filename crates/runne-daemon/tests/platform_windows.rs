//! Smoke test for Windows platform compatibility.
//!
//! Verifies basic platform identification on Windows.

#[cfg(target_os = "windows")]
#[test]
fn windows_smoke_platform_check() {
    assert!(std::path::Path::new(r"C:\").has_root());
}
