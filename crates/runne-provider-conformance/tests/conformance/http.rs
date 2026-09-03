use std::sync::{Arc, Mutex};

use crate::{shared::call, support::SECRET};
use futures::executor::block_on;
use runne_provider::{ProviderCapability, ProviderId, ProviderPort, StreamCursor, StreamError};
use runne_provider_conformance::{
    assert_credential_free, assert_redacted_diagnostics, validate_text_stream,
};
use runne_provider_http::{
    HttpProviderAdapter, HttpTransport, HttpTransportRequest, HttpTransportResponse,
    ProviderAdapterProfile, SecretMaterializer, TransportError,
};
use zeroize::Zeroizing;

type HttpObservation = (String, String, bool, bool, usize);

struct FixtureTransport {
    response: HttpTransportResponse,
    seen: Arc<Mutex<Vec<HttpObservation>>>,
}
impl HttpTransport for FixtureTransport {
    fn send(&self, request: HttpTransportRequest) -> Result<HttpTransportResponse, TransportError> {
        self.seen.lock().unwrap().push((
            request.origin.clone(),
            request.path.clone(),
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
        Ok(Zeroizing::new(SECRET.to_vec()))
    }
}

#[test]
fn adapter_conforms_to_its_exposed_synthetic_contract() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let profile = ProviderAdapterProfile {
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
    };
    let response = HttpTransportResponse {
        origin: profile.origin.clone(),
        path: profile.path.clone(),
        body: include_bytes!("../../fixtures/http_stream_fragments.json").to_vec(),
    };
    let adapter = HttpProviderAdapter::new(
        profile.clone(),
        FixtureTransport {
            response,
            seen: Arc::clone(&seen),
        },
        FixtureSecret,
    )
    .unwrap();
    let request_call = call(
        "fixture-provider",
        "fixture-model",
        "2026-07-28",
        serde_json::json!({"profile_digest":"07".repeat(32),"pricing_digest":"08".repeat(32)}),
    );
    let prepared = adapter.prepare(&request_call).unwrap();
    assert_credential_free(prepared.rendered_bytes(), SECRET).unwrap();
    let secret_response = HttpTransportResponse {
        origin: profile.origin.clone(),
        path: profile.path,
        body: SECRET.to_vec(),
    };
    assert_redacted_diagnostics(SECRET, &format!("{secret_response:?}"), "").unwrap();
    let stream = block_on(adapter.dispatch(dispatch_request(&prepared))).unwrap();
    let mut cursor = StreamCursor::new(0);
    let mut events = Vec::new();
    loop {
        match block_on(adapter.next(&stream, cursor)) {
            Ok(item) => {
                cursor = StreamCursor::new(item.event().sequence() + 1);
                events.push(item.event().clone());
            }
            Err(StreamError::Closed) => break,
            Err(error) => panic!("unexpected stream error: {error}"),
        }
    }
    validate_text_stream(&events, "synthetic response", false).unwrap();
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        &[(
            "https://provider.invalid".into(),
            "/v1/responses".into(),
            false,
            false,
            SECRET.len()
        )]
    );
    assert_eq!(
        block_on(adapter.cancel(runne_provider::CancelRequest::new(stream))).unwrap(),
        runne_provider::CancelDisposition::Requested
    );
    assert_eq!(
        block_on(adapter.cancel(runne_provider::CancelRequest::new(stream))).unwrap(),
        runne_provider::CancelDisposition::AlreadyRequested
    );
}

fn dispatch_request(prepared: &runne_provider::PreparedRequest) -> runne_provider::DispatchRequest {
    runne_provider::DispatchRequest::new(
        prepared.clone(),
        runne_provider::ProviderDispatchClaim {
            provider_id: ProviderId::new("fixture-provider").unwrap(),
            call_id: prepared.call().call_id(),
            attempt_id: runne_provider::DispatchAttemptId::from_bytes([3; 16]),
            permit_id: [4; 16],
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: [7; 32],
            token_reservation_id: [5; 16],
            cost_reservation_id: [6; 16],
            fencing_token: 1,
            provider_idempotency_key: "request-1".into(),
        },
    )
    .unwrap()
}
