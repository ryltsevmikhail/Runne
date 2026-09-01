#[test]
fn test_support_exposes_no_raw_measurement_or_revalidation_constructor() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let measurement = std::fs::read_to_string(workspace.join(
        "crates/runne-platform-desktop/src/updater_metadata/enrollment_tuple/measurement.rs",
    ))
    .expect("measurement source");
    let installed = std::fs::read_to_string(
        workspace.join("crates/runne-platform-desktop/src/updater_coordinator/installed_tuple.rs"),
    )
    .expect("installed tuple source");

    assert!(!measurement.contains("pub fn new("));
    assert!(!installed.contains("pub fn test_only_revalidate_confirmed_native_enrollment_at("));
}

#[test]
fn no_production_dependency_enables_platform_test_support() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut manifests = vec![workspace.join("apps/desktop/src-tauri/Cargo.toml")];
    manifests.extend(
        std::fs::read_dir(workspace.join("crates"))
            .expect("workspace crates")
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("Cargo.toml"))
            .filter(|path| path.is_file()),
    );
    for path in manifests {
        let source = std::fs::read_to_string(&path).expect("workspace manifest");
        let mut development = false;
        for line in source.lines() {
            if line.starts_with('[') {
                development = line.contains("dev-dependencies");
            }
            if line.starts_with("runne-platform-desktop =") && line.contains("test-support") {
                assert!(development, "production test-support dependency: {path:?}");
            }
        }
    }
}
