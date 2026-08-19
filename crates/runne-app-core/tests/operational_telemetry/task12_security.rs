use std::io::{Read, Write};
use std::net::TcpListener;

use runne_runtime_client::{
    REQUIRED_RUNTIME_CAPABILITIES, RuntimeSessionInfo, mock_authenticated_runtime_client,
};

use super::{AppCore, RuntimeMode};

const MARKERS: &[&str] = &[
    "task3-authorization-marker",
    "task3-credential-marker",
    "task3-api-token-marker",
    "task3-prompt-marker",
    "task3-output-marker",
    "task3-provider-body-marker",
    "task3-sse-marker",
    "task3-raw-error-marker",
    "task3-path-marker",
];

#[test]
fn app_core_serialized_projection_excludes_rejected_provider_body_marker() {
    let body_marker = "task3-provider-body-marker";
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        let body = format!(r#"{{"providerBody":"{body_marker}"}}"#);
        write!(stream, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\n\r\n{body}", body.len()).unwrap();
    });
    let client = mock_authenticated_runtime_client(
        &origin,
        RuntimeSessionInfo {
            profile_id: "runne-ui-client/2".to_owned(),
            schema_hash: "test".to_owned(),
            runtime_version: "test".to_owned(),
            capabilities: REQUIRED_RUNTIME_CAPABILITIES
                .iter()
                .map(ToString::to_string)
                .collect(),
            authority_id: "authority".to_owned(),
            principal_id: "principal".to_owned(),
            event_log_lineage_id: "lineage".to_owned(),
            daemon_instance_id: "daemon".to_owned(),
            launch_generation: 1,
            session_id: "session".to_owned(),
            authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".to_owned(),
            certificate_sha256: "11".repeat(32),
            capability_digest: "22".repeat(32),
        },
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let core =
        AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), client).unwrap();
    let serialized = String::from_utf8(
        serde_json::to_vec(&core.operational_telemetry_snapshot(10).unwrap()).unwrap(),
    )
    .unwrap();
    for marker in MARKERS {
        assert!(!serialized.contains(marker));
    }
    server.join().unwrap();
}

#[test]
fn app_core_telemetry_projection_has_no_direct_runtime_or_dynamic_payload_types() {
    for path in [
        "src/lib_parts/operational_telemetry.rs",
        "src/lib_parts/operational_telemetry_snapshot.rs",
        "src/lib_parts/operational_telemetry_state.rs",
    ] {
        let source =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
                .unwrap();
        for forbidden in [
            "runne_api::",
            "runne_runtime::",
            "serde_json::Value",
            "HashMap",
            "BTreeMap",
            ": String",
            "source: ",
        ] {
            assert!(!source.contains(forbidden), "{path} contains {forbidden}");
        }
    }
    let _ = RuntimeMode::Bundled;
}
