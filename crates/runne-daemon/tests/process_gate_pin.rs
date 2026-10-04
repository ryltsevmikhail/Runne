//! Regression pin: the helper-process channel denies before any native
//! provider access (start and recovery re-adopt share `with_process_root`).
#![cfg(all(feature = "test-support", feature = "desktop-protected"))]

#[test]
fn process_channel_denies_structurally_before_native_access() {
    let directory = tempfile::tempdir().unwrap();
    runne_daemon::application::process_gate_fixture::process_channel_denies_before_native_access(
        directory.path(),
    );
}
