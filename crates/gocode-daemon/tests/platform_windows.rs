//! Smoke test for Windows platform compatibility.
//!
//! Verifies basic platform identification on Windows.

#[cfg(target_os = "windows")]
#[test]
fn windows_smoke_platform_check() {
    // Windows-specific: verify we're on windows
    assert!(cfg!(windows));
}
