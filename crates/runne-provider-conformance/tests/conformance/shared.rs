use std::collections::BTreeMap;

use crate::support::SECRET;
use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderTextInput,
};
use runne_provider_conformance::{
    RequestContract, WireRequest, assert_credential_free, assert_redacted_diagnostics,
};

pub fn call(
    provider: &str,
    model: &str,
    revision: &str,
    extension: serde_json::Value,
) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([7; 16]),
        ModelRef::new(ProviderId::new(provider).unwrap(), model, revision).unwrap(),
        [9; 32],
        32,
        extension,
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming])
}

pub fn assert_routed_request(method: &str, origin: &str, path: &str, body: &[u8]) {
    let mut headers = BTreeMap::new();
    headers.insert("Authorization".into(), SECRET.to_vec());
    headers.insert("Content-Type".into(), b"application/json".to_vec());
    headers.insert("X-Client-Request-Id".into(), b"request-1".to_vec());
    let request = WireRequest::new(method, origin, path, headers, body.to_vec());
    RequestContract::new(method, origin, path)
        .require_header("authorization")
        .require_header("content-type")
        .require_header("x-client-request-id")
        .validate(&request)
        .unwrap();
    assert_credential_free(body, SECRET).unwrap();
    assert_redacted_diagnostics(SECRET, &format!("{request:?}"), &request.to_string()).unwrap();
}

#[test]
fn common_classifier_covers_rate_limit_timeout_transport_and_cancellation() {
    let cases = [
        (
            Some(429),
            Some("rate_limited"),
            runne_provider_conformance::ProviderFailureKind::RateLimited,
            true,
        ),
        (
            None,
            Some("timeout"),
            runne_provider_conformance::ProviderFailureKind::Timeout,
            true,
        ),
        (
            None,
            Some("transport"),
            runne_provider_conformance::ProviderFailureKind::Transport,
            true,
        ),
        (
            None,
            Some("cancelled"),
            runne_provider_conformance::ProviderFailureKind::Cancelled,
            false,
        ),
    ];
    for (status, code, kind, retryable) in cases {
        let failure = runne_provider_conformance::classify_provider_failure(status, code, Some(11));
        assert_eq!(failure.kind(), kind);
        assert_eq!(failure.retry().retryable(), retryable);
    }
    assert_eq!(
        runne_provider_conformance::classify_provider_failure(
            Some(429),
            Some("rate_limited"),
            Some(11),
        )
        .retry()
        .retry_after_seconds(),
        Some(11)
    );
}
