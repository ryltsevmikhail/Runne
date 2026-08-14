use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use super::super::{
    OperationalTelemetryHttpState, no_store_response, operational_telemetry_router,
};
use crate::auth::SessionAuthLayer;
use axum::{body::Body, http::Request};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use gocode_api::{
    ApiPrincipalId, DaemonInstanceId, OperationalTelemetryQueryErrorV1,
    OperationalTelemetryQueryPort, RecoveryObservationStatusV1,
    RuntimeOperationalTelemetrySnapshotV1, RuntimeSessionBinding, StableRuntimeBinding,
    TelemetryCompletenessV1, TelemetryFreshnessV1, TelemetrySectionMetaV1,
};
use gocode_application::local_session::{
    BootstrapProof, LocalSessionService, bootstrap_proof_transcript,
};
use gocode_domain::{event::Sensitivity, id::EventLogLineageId};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower::ServiceExt;

pub(super) const PATH: &str = "/v1/runtime/operational-telemetry";

#[derive(Clone, Copy)]
pub(super) enum QueryOutcome {
    Available,
    Unavailable,
}

pub(super) struct Query {
    pub(super) calls: AtomicUsize,
    outcome: QueryOutcome,
}

impl Query {
    pub(super) fn new(outcome: QueryOutcome) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            outcome,
        }
    }
}

impl OperationalTelemetryQueryPort for Query {
    fn query_operational_telemetry(
        &self,
    ) -> Result<RuntimeOperationalTelemetrySnapshotV1, OperationalTelemetryQueryErrorV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.outcome {
            QueryOutcome::Available => Ok(snapshot()),
            QueryOutcome::Unavailable => Err(OperationalTelemetryQueryErrorV1::Unavailable),
        }
    }
}

fn snapshot() -> RuntimeOperationalTelemetrySnapshotV1 {
    let unavailable = TelemetrySectionMetaV1::new(
        1,
        TelemetryFreshnessV1::Unavailable,
        TelemetryCompletenessV1::Unavailable,
    )
    .unwrap();
    RuntimeOperationalTelemetrySnapshotV1::new(
        1,
        1,
        gocode_api::RuntimeDurableOperationalTelemetryV1::new(
            unavailable.clone(),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap(),
        gocode_api::RuntimeRecoveryTransientV1::new(
            unavailable,
            RecoveryObservationStatusV1::Unavailable,
            None,
            0,
            false,
        )
        .unwrap(),
    )
    .unwrap()
}

fn binding() -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
            ApiPrincipalId::new("local-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000003"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "gocode-ui-client/2",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2]),
        1,
        [5; 16],
        0,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap()
}

fn session_authorization(binding: &RuntimeSessionBinding) -> axum::http::HeaderValue {
    let mut service = LocalSessionService::new(binding.clone(), [7; 32]);
    let challenge = service
        .issue_challenge([8; 32], [9; 32], Duration::ZERO)
        .unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&[7; 32]).unwrap();
    mac.update(&bootstrap_proof_transcript(binding, [9; 32], [8; 32]));
    service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            [10; 32],
            Duration::ZERO,
        )
        .unwrap();
    format!("GocodeSession {}", URL_SAFE_NO_PAD.encode([10; 32]))
        .parse()
        .unwrap()
}

pub(super) fn app(query: Arc<Query>) -> (axum::Router, axum::http::HeaderValue) {
    let binding = binding();
    let authorization = session_authorization(&binding);
    let session_service = Arc::new(Mutex::new(LocalSessionService::new(
        binding.clone(),
        [7; 32],
    )));
    let mut service = session_service.lock().unwrap();
    let challenge = service
        .issue_challenge([8; 32], [9; 32], Duration::ZERO)
        .unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&[7; 32]).unwrap();
    mac.update(&bootstrap_proof_transcript(&binding, [9; 32], [8; 32]));
    service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            [10; 32],
            Duration::ZERO,
        )
        .unwrap();
    drop(service);
    (
        operational_telemetry_router(OperationalTelemetryHttpState::new(query))
            .layer(SessionAuthLayer::new(
                session_service,
                binding,
                Arc::new(|| Duration::ZERO),
            ))
            .layer(axum::middleware::from_fn(no_store_response)),
        authorization,
    )
}

pub(super) async fn request(
    app: axum::Router,
    authorization: &axum::http::HeaderValue,
    method: &str,
    body: Body,
) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(method)
            .uri(PATH)
            .header("authorization", authorization.clone())
            .body(body)
            .unwrap(),
    )
    .await
    .unwrap()
}

pub(super) fn assert_no_store(response: &axum::response::Response) {
    assert_eq!(response.headers()["cache-control"], "no-store");
}
