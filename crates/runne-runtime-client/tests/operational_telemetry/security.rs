use runne_runtime_client::RuntimeApiErrorKind;

use crate::support::*;

const ATTACKS: &[(&str, &str)] = &[
    ("authorization", "task3-authorization-marker"),
    ("Authorization", "task3-authorization-marker"),
    ("credential", "task3-credential-marker"),
    ("api_token", "task3-api-token-marker"),
    ("api-token", "task3-api-token-marker"),
    ("api.token", "task3-api-token-marker"),
    ("api token", "task3-api-token-marker"),
    ("prompt", "task3-prompt-marker"),
    ("output", "task3-output-marker"),
    ("providerBody", "task3-provider-body-marker"),
    ("provider_body", "task3-provider-body-marker"),
    ("provider-body", "task3-provider-body-marker"),
    ("sse", "task3-sse-marker"),
    ("chunk", "task3-sse-marker"),
    ("rawError", "task3-raw-error-marker"),
    ("raw_error", "task3-raw-error-marker"),
    ("exception", "task3-raw-error-marker"),
    ("secretPath", "task3-path-marker"),
    ("secret_path", "task3-path-marker"),
    ("endpoint", "task3-path-marker"),
    ("url", "task3-path-marker"),
    ("headers", "task3-authorization-marker"),
];

#[tokio::test]
async fn strict_client_rejects_direct_nested_and_alias_marker_wire_without_diagnostics() {
    for (key, marker) in ATTACKS {
        for body in [
            valid_snapshot(1).replacen('{', &format!(r#"{{"{key}":"{marker}","#), 1),
            valid_snapshot(1).replacen(
                r#""tokens":{"#,
                &format!(r#""tokens":{{"{key}":"{marker}","#),
                1,
            ),
        ] {
            let (client, request) = client_for(response(200, &[], body), true, 1).await;
            let error = telemetry_error(client.operational_telemetry().await);
            assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
            assert!(!format!("{error:?}").contains(marker));
            assert!(!error.to_string().contains(marker));
            request.await.expect("fixture request");
        }
    }
}

#[test]
fn runtime_client_telemetry_source_has_no_unbounded_or_raw_projection_path() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/canonical/operational_telemetry.rs"),
    )
    .unwrap();
    for forbidden in [
        "serde_json::Value",
        "response.bytes()",
        "response.text()",
        "response.json()",
        "HashMap",
        "BTreeMap",
        ": String",
        "source: ",
    ] {
        assert!(!source.contains(forbidden), "contains {forbidden}");
    }
}
