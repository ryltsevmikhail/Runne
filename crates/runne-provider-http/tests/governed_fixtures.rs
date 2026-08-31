use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use runne_provider::{
    DispatchAttemptId, DispatchError, DispatchRequest, ModelRef, ProviderCall, ProviderCallId,
    ProviderCapability, ProviderDispatchClaim, ProviderId, ProviderPort, ReconcileRequest,
    ReconciliationDisposition, StreamCursor,
};
use runne_provider_http::{
    HttpProviderAdapter, HttpTransport, HttpTransportRequest, HttpTransportResponse,
    ProviderAdapterProfile, SecretMaterializer, TransportError,
};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
struct TransportObservation {
    follow_redirects: bool,
    use_ambient_proxy: bool,
    authorization_bytes: usize,
    provider_idempotency_key: String,
}

struct FixtureTransport {
    response: HttpTransportResponse,
    observed: Arc<Mutex<Vec<TransportObservation>>>,
}

impl HttpTransport for FixtureTransport {
    fn send(&self, request: HttpTransportRequest) -> Result<HttpTransportResponse, TransportError> {
        self.observed.lock().unwrap().push(TransportObservation {
            follow_redirects: request.follow_redirects,
            use_ambient_proxy: request.use_ambient_proxy,
            authorization_bytes: request.authorization.len(),
            provider_idempotency_key: request.provider_idempotency_key.clone(),
        });
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
            observed: Arc::new(Mutex::new(Vec::new())),
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

fn dispatch_request(
    prepared: runne_provider::PreparedRequest,
    attempt_id: DispatchAttemptId,
    provider_idempotency_key: &str,
) -> DispatchRequest {
    let claim = ProviderDispatchClaim {
        provider_id: ProviderId::new("fixture-provider").unwrap(),
        call_id: prepared.call().call_id(),
        attempt_id,
        permit_id: [4; 16],
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: [7; 32],
        token_reservation_id: [8; 16],
        cost_reservation_id: [9; 16],
        fencing_token: 1,
        provider_idempotency_key: provider_idempotency_key.to_owned(),
    };
    DispatchRequest::new(prepared, claim).unwrap()
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
    let observed = Arc::new(Mutex::new(Vec::new()));
    let adapter = HttpProviderAdapter::new(
        profile(),
        FixtureTransport {
            response: valid_response(),
            observed: Arc::clone(&observed),
        },
        FixtureSecret,
    )
    .unwrap();
    let prepared = adapter
        .prepare(&call(&"07".repeat(32), &"08".repeat(32)))
        .unwrap();
    let stream = block_on(adapter.dispatch(dispatch_request(
        prepared,
        DispatchAttemptId::from_bytes([3; 16]),
        "gocode-provider-c436f15d42859a67270a2f39ff1c8508",
    )))
    .unwrap();
    let started = block_on(adapter.next(&stream, StreamCursor::new(0))).unwrap();
    assert_eq!(started.event().sequence(), 0);
    assert_eq!(
        observed.lock().unwrap().as_slice(),
        &[TransportObservation {
            follow_redirects: false,
            use_ambient_proxy: false,
            authorization_bytes: 24,
            provider_idempotency_key: "gocode-provider-c436f15d42859a67270a2f39ff1c8508".into(),
        }]
    );
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
            observed: Arc::new(Mutex::new(Vec::new())),
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
    block_on(adapter.dispatch(dispatch_request(first, attempt, "fixture-attempt-replay"))).unwrap();

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

    assert!(
        block_on(adapter.dispatch(dispatch_request(changed, attempt, "fixture-attempt-replay")))
            .is_err()
    );
}

#[test]
fn invalid_remote_response_never_reconciles_as_absent() {
    let mut response = valid_response();
    response.body = b"{invalid-response".to_vec();
    let adapter = adapter(response);
    let attempt = DispatchAttemptId::from_bytes([4; 16]);
    let prepared = adapter
        .prepare(&call(&"07".repeat(32), &"08".repeat(32)))
        .unwrap();

    assert_eq!(
        block_on(adapter.dispatch(dispatch_request(
            prepared,
            attempt,
            "fixture-ambiguous-response"
        ))),
        Err(DispatchError::MaybeDispatched)
    );
    assert_eq!(
        block_on(adapter.reconcile(ReconcileRequest::new(attempt))).unwrap(),
        ReconciliationDisposition::Uncertain
    );
}

fn dispatch_once(
    adapter: HttpProviderAdapter<FixtureTransport, FixtureSecret>,
) -> Result<runne_provider::ProviderStreamId, runne_provider::DispatchError> {
    let prepared = adapter
        .prepare(&call(&"07".repeat(32), &"08".repeat(32)))
        .unwrap();
    block_on(adapter.dispatch(dispatch_request(
        prepared,
        DispatchAttemptId::from_bytes([3; 16]),
        "fixture-dispatch-once",
    )))
}
