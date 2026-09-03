use std::collections::BTreeMap;

use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind, ProviderUsage,
};
use runne_provider_conformance::{
    ALL_FIXTURE_IDS, CancellationDisposition, RequestContract, ScriptedOutcome, ScriptedTransport,
    WireRequest, assert_credential_free, assert_redacted_diagnostics, classify_provider_failure,
    fixture, normalize_identifier, validate_text_stream,
};

const SECRET: &[u8] = b"fixture-secret-never-log";

fn event(sequence: u64, kind: ProviderStreamEventKind) -> ProviderStreamEvent {
    ProviderStreamEvent::new(sequence, kind).expect("valid normalized event")
}

fn successful_events() -> Vec<ProviderStreamEvent> {
    vec![
        event(0, ProviderStreamEventKind::Started),
        event(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "hello ".into(),
            },
        ),
        event(
            2,
            ProviderStreamEventKind::TextDelta {
                text: "world".into(),
            },
        ),
        event(
            3,
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(2, 3, 0, 0).expect("bounded usage"),
            },
        ),
        event(
            4,
            ProviderStreamEventKind::Finished {
                disposition: runne_provider::ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        ),
    ]
}

#[test]
fn identifiers_are_trimmed_lowercase_and_bounded() {
    let normalized = normalize_identifier(" provider ", " Model-5 ", " REV-1 ").unwrap();
    assert_eq!(normalized.provider_id(), "provider");
    assert_eq!(normalized.model_id(), "model-5");
    assert_eq!(normalized.revision(), "rev-1");
    assert!(normalize_identifier(" ", "model", "rev").is_err());
    assert!(normalize_identifier("provider", "model name", "rev").is_err());
}

#[test]
fn request_contract_checks_route_headers_and_diagnostics_without_values() {
    let mut headers = BTreeMap::new();
    headers.insert("Authorization".into(), SECRET.to_vec());
    headers.insert("Content-Type".into(), b"application/json".to_vec());
    headers.insert("X-Client-Request-Id".into(), b"request-1".to_vec());
    let request = WireRequest::new(
        "POST",
        "https://provider.invalid",
        "/v1/responses",
        headers,
        br#"{"model":"fixture-model"}"#.to_vec(),
    );
    RequestContract::new("POST", "https://provider.invalid", "/v1/responses")
        .require_header("authorization")
        .require_header("content-type")
        .require_header("x-client-request-id")
        .validate(&request)
        .unwrap();
    assert_credential_free(br#"{"model":"fixture-model"}"#, SECRET).unwrap();
    let debug = format!("{request:?}");
    let display = request.to_string();
    assert_redacted_diagnostics(SECRET, &debug, &display).unwrap();
}

#[test]
fn normalized_stream_requires_text_usage_and_terminal() {
    let evidence = validate_text_stream(&successful_events(), "hello world", true).unwrap();
    assert_eq!(evidence.text_delta_count(), 2);
    assert_eq!(evidence.text_bytes(), 11);
    assert!(evidence.usage_available());
    let mut incomplete = successful_events();
    incomplete.pop();
    assert!(validate_text_stream(&incomplete, "hello world", true).is_err());
    assert!(validate_text_stream(&[], "", false).is_err());
}

#[test]
fn failures_are_typed_and_retry_metadata_is_deterministic() {
    let auth = classify_provider_failure(Some(401), Some("authentication_failed"), None);
    assert_eq!(
        auth.kind(),
        runne_provider_conformance::ProviderFailureKind::Authentication
    );
    let rate = classify_provider_failure(Some(429), Some("rate_limited"), Some(17));
    assert_eq!(
        rate.kind(),
        runne_provider_conformance::ProviderFailureKind::RateLimited
    );
    assert!(rate.retry().retryable());
    assert_eq!(rate.retry().retry_after_seconds(), Some(17));
    let unknown_model = classify_provider_failure(Some(404), Some("model_unavailable"), None);
    assert_eq!(
        unknown_model.kind(),
        runne_provider_conformance::ProviderFailureKind::ModelUnavailable
    );
    let timeout = classify_provider_failure(None, Some("timeout"), None);
    assert_eq!(
        timeout.kind(),
        runne_provider_conformance::ProviderFailureKind::Timeout
    );
    let rendered = format!("{auth:?} {auth}");
    assert_redacted_diagnostics(SECRET, &rendered, "").unwrap();
}

#[test]
fn scripted_transport_replays_offline_actions_and_cancellation() {
    let mut transport = ScriptedTransport::new([
        ScriptedOutcome::response(b"success-fixture".to_vec()),
        ScriptedOutcome::timeout(),
    ]);
    let request = WireRequest::new(
        "POST",
        "https://provider.invalid",
        "/v1/responses",
        BTreeMap::new(),
        b"body".to_vec(),
    );
    assert_eq!(transport.send(&request).unwrap(), b"success-fixture");
    assert_eq!(
        transport.send(&request).unwrap_err().kind(),
        runne_provider_conformance::ProviderFailureKind::Timeout
    );
    assert_eq!(transport.observations().len(), 2);
    assert_eq!(transport.cancel(), CancellationDisposition::Requested);
    assert_eq!(
        transport.cancel(),
        CancellationDisposition::AlreadyRequested
    );

    let mut fault_transport =
        ScriptedTransport::new([ScriptedOutcome::Transport, ScriptedOutcome::Cancelled]);
    assert_eq!(
        fault_transport.send(&request).unwrap_err().kind(),
        runne_provider_conformance::ProviderFailureKind::Transport
    );
    assert_eq!(
        fault_transport.send(&request).unwrap_err().kind(),
        runne_provider_conformance::ProviderFailureKind::Cancelled
    );
}

#[test]
fn governed_fixtures_are_json_and_contain_no_secret_literals() {
    for fixture_id in ALL_FIXTURE_IDS {
        let bytes = fixture(fixture_id);
        serde_json::from_slice::<serde_json::Value>(bytes).expect("fixture JSON");
        assert!(!bytes.windows(SECRET.len()).any(|window| window == SECRET));
    }
}
