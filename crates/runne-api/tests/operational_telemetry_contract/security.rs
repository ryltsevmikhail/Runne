use super::*;

const AUTHORIZATION: &str = "task3-authorization-marker";
const CREDENTIAL: &str = "task3-credential-marker";
const TOKEN: &str = "task3-api-token-marker";
const PROMPT: &str = "task3-prompt-marker";
const OUTPUT: &str = "task3-output-marker";
const BODY: &str = "task3-provider-body-marker";
const SSE: &str = "task3-sse-marker";
const ERROR: &str = "task3-raw-error-marker";
const PATH: &str = "task3-path-marker";

const FORBIDDEN_TELEMETRY_WIRE_KEYS_AND_ALIASES: &[(&str, &str)] = &[
    ("authorization", AUTHORIZATION),
    ("Authorization", AUTHORIZATION),
    ("AUTHORIZATION", AUTHORIZATION),
    ("credential", CREDENTIAL),
    ("Credential", CREDENTIAL),
    ("CREDENTIAL", CREDENTIAL),
    ("token", TOKEN),
    ("Token", TOKEN),
    ("TOKEN", TOKEN),
    ("apiToken", TOKEN),
    ("api_token", TOKEN),
    ("api-token", TOKEN),
    ("api.token", TOKEN),
    ("api token", TOKEN),
    ("prompt", PROMPT),
    ("Prompt", PROMPT),
    ("PROMPT", PROMPT),
    ("output", OUTPUT),
    ("Output", OUTPUT),
    ("OUTPUT", OUTPUT),
    ("body", BODY),
    ("Body", BODY),
    ("BODY", BODY),
    ("providerBody", BODY),
    ("provider_body", BODY),
    ("provider-body", BODY),
    ("provider.body", BODY),
    ("provider body", BODY),
    ("sse", SSE),
    ("SSE", SSE),
    ("chunk", SSE),
    ("error", ERROR),
    ("rawError", ERROR),
    ("raw_error", ERROR),
    ("raw-error", ERROR),
    ("raw.error", ERROR),
    ("raw error", ERROR),
    ("exception", ERROR),
    ("path", PATH),
    ("secretPath", PATH),
    ("secret_path", PATH),
    ("secret-path", PATH),
    ("secret.path", PATH),
    ("secret path", PATH),
    ("endpoint", PATH),
    ("url", PATH),
    ("URL", PATH),
    ("headers", AUTHORIZATION),
    ("Headers", AUTHORIZATION),
    ("HEADERS", AUTHORIZATION),
    ("requestHeaders", AUTHORIZATION),
    ("request_headers", AUTHORIZATION),
    ("request-headers", AUTHORIZATION),
];

#[test]
fn public_wire_rejects_direct_nested_and_alias_marker_fields_without_reflection() {
    for (key, marker) in FORBIDDEN_TELEMETRY_WIRE_KEYS_AND_ALIASES {
        for body in [
            std::str::from_utf8(VALID_SNAPSHOT).unwrap().replacen(
                "{",
                &format!("{{\"{key}\":\"{marker}\","),
                1,
            ),
            std::str::from_utf8(VALID_SNAPSHOT).unwrap().replacen(
                "\"tokens\":{",
                &format!("\"tokens\":{{\"{key}\":\"{marker}\","),
                1,
            ),
        ] {
            let error = match serde_json::from_str::<RuntimeOperationalTelemetrySnapshotV1>(&body) {
                Ok(_) => panic!("forbidden telemetry field must be rejected"),
                Err(error) => error,
            };
            assert!(!format!("{error:?}").contains(marker));
            assert!(!error.to_string().contains(marker));
        }
    }

    let snapshot = serde_json::from_slice::<RuntimeOperationalTelemetrySnapshotV1>(VALID_SNAPSHOT)
        .expect("valid closed snapshot");
    let serialized = String::from_utf8(serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let static_error = runne_api::OperationalTelemetryQueryErrorV1::Unavailable;
    for marker in [
        AUTHORIZATION,
        CREDENTIAL,
        TOKEN,
        PROMPT,
        OUTPUT,
        BODY,
        SSE,
        ERROR,
        PATH,
    ] {
        assert!(!serialized.contains(marker));
        assert!(!format!("{static_error:?}").contains(marker));
        assert!(!static_error.to_string().contains(marker));
    }
}

#[test]
fn api_telemetry_sources_remain_closed_and_payload_free() {
    for path in [
        "src/operational_telemetry.rs",
        "src/operational_telemetry/core.rs",
        "src/operational_telemetry/runtime.rs",
        "src/operational_telemetry/wire.rs",
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
            "raw_error",
        ] {
            assert!(!source.contains(forbidden), "{path} contains {forbidden}");
        }
    }
}
