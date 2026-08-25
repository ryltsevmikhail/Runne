#[test]
fn runtime_device_is_safe_and_unconfigured_without_a_session() {
    let directory = tempfile::tempdir().expect("temp directory");
    let core = AppCore::open(&directory.path().join("profile.sqlite3")).expect("open core");

    assert_eq!(
        core.runtime_device().expect("device snapshot"),
        super::RuntimeDeviceSnapshot {
            connection: RuntimeAvailability::Unconfigured,
            authenticated: false,
            runtime_version: None,
            launch_generation: None,
        }
    );
    let debug = format!("{:?}", core.runtime_device().expect("device snapshot"));
    assert!(!debug.contains("token"));
    assert!(!debug.contains("127.0.0.1"));
}
