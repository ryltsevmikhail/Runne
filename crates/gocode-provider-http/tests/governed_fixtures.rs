use std::sync::Mutex;

use futures::executor::block_on;
use gocode_provider::{
    DispatchAttemptId, DispatchRequest, ModelRef, ProviderCall, ProviderCallId, ProviderCapability,
    ProviderId, ProviderPort, StreamCursor,
};
use gocode_provider_http::{
    HttpProviderAdapter, HttpTransport, HttpTransportRequest, HttpTransportResponse,
    ProviderAdapterProfile, SecretMaterializer, TransportError,
};
use zeroize::Zeroizing;

struct FixtureTransport {
    response: HttpTransportResponse,
    observed: Mutex<Vec<(bool, bool, usize)>>,
}

impl HttpTransport for FixtureTransport {
    fn send(&self, request: HttpTransportRequest) -> Result<HttpTransportResponse, TransportError> {
        self.observed.lock().unwrap().push((
            request.follow_redirects,
            request.use_ambient_proxy,
            request.authorization.len(),
        ));
        Ok(self.response.clone())
    }
}

struct FixtureSecret;

impl SecretMaterializer for FixtureSecret {
    fn materialize(&self) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        Ok(Zeroizing::new(b"fixture-secret-never-log".to_vec()))
    }
}

fn profile() -> ProviderAdapterProfile {
    ProviderAdapterProfile {
        profile_digest: [7; 32],
        provider_id: ProviderId::new("fixture-provider").unwrap(),
        model_id: "fixture-model".into(),
        model_revision: "2026-07-28".into(),
        pricing_digest: [8; 32],
        origin: "https://provider.invalid".into(),
        path: "/v1/responses".into(),
        max_body_bytes: 16_384,
        max_frame_bytes: 1_024,
        capabilities: vec![ProviderCapability::Streaming],
    }
}

fn call(profile_digest: &str, pricing_digest: &str) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([1; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-28",
        )
        .unwrap(),
        [2; 32],
        1_024,
        serde_json::json!({
            "profile_digest": profile_digest,
            "pricing_digest": pricing_digest
        }),
    )
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming])
}

fn adapter(
    response: HttpTransportResponse,
) -> HttpProviderAdapter<FixtureTransport, FixtureSecret> {
    HttpProviderAdapter::new(
        profile(),
        FixtureTransport {
            response,
            observed: Mutex::new(Vec::new()),
        },
        FixtureSecret,
    )
    .unwrap()
}

fn valid_response() -> HttpTransportResponse {
    HttpTransportResponse {
        origin: "https://provider.invalid".into(),
        path: "/v1/responses".into(),
        body: include_bytes!("fixtures/synthetic_stream.json").to_vec(),
    }
}

#[test]
fn exact_profile_and_pricing_digests_are_required_before_dispatch() {
    let adapter = adapter(valid_response());
    let valid_profile = "07".repeat(32);
    let valid_pricing = "08".repeat(32);
    assert!(
        adapter
            .prepare(&call(&valid_profile, &valid_pricing))
            .is_ok()
    );
    assert!(
        adapter
            .prepare(&call(&"00".repeat(32), &valid_pricing))
            .is_err()
    );
    assert!(
        adapter
            .prepare(&call(&valid_profile, &"00".repeat(32)))
            .is_err()
    );
}

#[test]
fn transport_disables_redirects_and_ambient_proxy_and_normalizes_fixture() {
    let adapter = adapter(valid_response());
    let prepared = adapter
        .prepare(&call(&"07".repeat(32), &"08".repeat(32)))
        .unwrap();
    let stream = block_on(adapter.dispatch(DispatchRequest::new(
        prepared,
        DispatchAttemptId::from_bytes([3; 16]),
    )))
    .unwrap();
    let started = block_on(adapter.next(&stream, StreamCursor::new(0))).unwrap();
    assert_eq!(started.event().sequence(), 0);
}

#[test]
fn origin_path_unknown_terminal_and_frame_bounds_fail_closed() {
    let mut response = valid_response();
    response.origin = "https://redirect.invalid".into();
    assert!(dispatch_once(adapter(response)).is_err());

    let mut response = valid_response();
    response.body = br#"{"events":[{"kind":"finished","reason":"future"}]}"#.to_vec();
    assert!(dispatch_once(adapter(response)).is_err());

    let mut bounded_profile = profile();
    bounded_profile.max_frame_bytes = 4;
    let adapter = HttpProviderAdapter::new(
        bounded_profile,
        FixtureTransport {
            response: valid_response(),
            observed: Mutex::new(Vec::new()),
        },
        FixtureSecret,
    )
    .unwrap();
    assert!(dispatch_once(adapter).is_err());
}

#[test]
fn diagnostics_never_contain_materialized_secret() {
    let error = TransportError::Unavailable.to_string();
    assert!(!error.contains("fixture-secret-never-log"));
}

#[test]
fn attempt_replay_requires_the_exact_prepared_request() {
    let adapter = adapter(valid_response());
    let first = adapter
        .prepare(&call(&"07".repeat(32), &"08".repeat(32)))
        .unwrap();
    let attempt = DispatchAttemptId::from_bytes([3; 16]);
    block_on(adapter.dispatch(DispatchRequest::new(first, attempt))).unwrap();

    let changed = ProviderCall::new(
        ProviderCallId::from_bytes([2; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-28",
        )
        .unwrap(),
        [9; 32],
        1_024,
        serde_json::json!({
            "profile_digest": "07".repeat(32),
            "pricing_digest": "08".repeat(32)
        }),
    )
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    let changed = adapter.prepare(&changed).unwrap();

    assert!(block_on(adapter.dispatch(DispatchRequest::new(changed, attempt))).is_err());
}

fn dispatch_once(
    adapter: HttpProviderAdapter<FixtureTransport, FixtureSecret>,
) -> Result<gocode_provider::ProviderStreamId, gocode_provider::DispatchError> {
    let prepared = adapter
        .prepare(&call(&"07".repeat(32), &"08".repeat(32)))
        .unwrap();
    block_on(adapter.dispatch(DispatchRequest::new(
        prepared,
        DispatchAttemptId::from_bytes([3; 16]),
    )))
}
