use std::sync::Arc;

use gocode_api::OperationalTelemetryQueryPort;
use gocode_domain::timestamp::Timestamp;
use gocode_observability::operational::RecoveryObservationRegistry;

use super::{FixedClock, make_service, store};

#[test]
fn daemon_unavailable_source_maps_diagnostics_to_a_static_public_error() {
    let error_marker = "task3-raw-error-marker";
    let path_marker = "task3-path-marker";
    let (directory, store) = store();
    rusqlite::Connection::open(directory.path().join("telemetry.sqlite"))
        .unwrap()
        .execute(
            "UPDATE provider_runtime_authority_state SET active = 0 WHERE id = 1",
            [],
        )
        .unwrap();
    let (registry, _) = RecoveryObservationRegistry::new();
    let service = make_service(
        store,
        Arc::new(registry),
        FixedClock(Timestamp::from_unix_micros(1_000_000)),
    );
    let error = match service.query_operational_telemetry() {
        Ok(_) => panic!("source must be unavailable"),
        Err(error) => error,
    };
    for marker in [error_marker, path_marker] {
        assert!(!format!("{error:?}").contains(marker));
        assert!(!error.to_string().contains(marker));
    }
}

#[test]
fn daemon_telemetry_composition_has_no_raw_diagnostic_or_store_projection() {
    for path in [
        "src/operational_telemetry.rs",
        "src/operational_telemetry/composition.rs",
        "src/operational_telemetry/store.rs",
        "src/operational_telemetry/unavailable.rs",
    ] {
        let source =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
                .unwrap();
        for forbidden in [
            "serde_json::Value",
            "HashMap",
            "BTreeMap",
            ": String",
            ".to_string()",
        ] {
            assert!(!source.contains(forbidden), "{path} contains {forbidden}");
        }
    }
}
