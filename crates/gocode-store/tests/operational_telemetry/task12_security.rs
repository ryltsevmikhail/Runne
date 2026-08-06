use gocode_application::provider::ProviderAdmissionError;
use gocode_store::provider::SqliteProviderExecutionStore;

#[test]
fn sqlite_failure_from_marker_bearing_path_maps_to_a_fieldless_source_error() {
    let path_marker = "task3-path-marker";
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(path_marker).join("telemetry.sqlite");
    let raw = rusqlite::Connection::open(&path).expect_err("missing marker parent must fail");
    assert!(format!("{raw:?}").contains(path_marker) || raw.to_string().contains(path_marker));

    let error = match SqliteProviderExecutionStore::open(&path) {
        Ok(_) => panic!("marker-bearing SQLite open must fail"),
        Err(error) => error,
    };
    assert_eq!(error, ProviderAdmissionError::RepositoryFailure);
    assert!(!format!("{error:?}").contains(path_marker));
    assert!(!error.to_string().contains(path_marker));
}

#[test]
fn sqlite_telemetry_sources_do_not_project_rows_or_raw_diagnostics() {
    for path in [
        "src/provider/operational_telemetry/mod.rs",
        "src/provider/operational_telemetry/accounting.rs",
        "src/provider/operational_telemetry/aggregates.rs",
        "src/provider/operational_telemetry/authority.rs",
        "src/provider/operational_telemetry/committed_effects.rs",
        "src/provider/operational_telemetry/guards.rs",
        "src/provider/operational_telemetry/runtime.rs",
        "src/provider/operational_telemetry/uncertain.rs",
    ] {
        let source =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
                .unwrap();
        for forbidden in [
            "serde_json::Value",
            "HashMap",
            "BTreeMap",
            ": String",
            "source: ",
        ] {
            assert!(!source.contains(forbidden), "{path} contains {forbidden}");
        }
    }
}
