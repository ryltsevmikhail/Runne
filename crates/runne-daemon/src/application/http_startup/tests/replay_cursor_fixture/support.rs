use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use runne_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use runne_application::{
    local_session::{BootstrapProof, LocalSessionService, bootstrap_proof_transcript},
    ports::{
        ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
        ReplayEvent,
    },
    prohibited_content::{
        CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
    },
    replay_service::ReplayService,
};
use runne_domain::{
    event::Sensitivity,
    id::EventLogLineageId,
    replay::{ReplayCursor, ReplayScope},
};
use runne_http::{
    auth::{SessionAuthLayer, session_authorization_header},
    limits::LimitsConfig,
    middleware::request_id_middleware,
    replay::{ReplayHttpBinding, ReplayHttpState, replay_router},
};
use serde_json::Value;
use std::sync::{Arc, Mutex};

mod store;
pub use store::*;

pub const ROOT_KEY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
pub const EVENT_ID: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x51,
];
pub const AGGREGATE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x52,
];
pub const LINEAGE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, 0x53,
];
pub const AUTHORITY: [u8; 16] = [0xa1; 16];
const SESSION_AUTHORITY: [u8; 32] = [0xac; 32];
const BOOTSTRAP_KEY: [u8; 32] = [0xab; 32];

pub fn fixture_event() -> ReplayEvent {
    ReplayEvent {
        global_position: 9,
        event_id: EVENT_ID,
        aggregate_type: 2,
        aggregate_id: AGGREGATE,
        payload: vec![],
        timestamp: 1_725_000_000_000_000,
        event_type: "conversation.message.created".into(),
        sequence: 3,
        sensitivity: 1,
        schema_version: 1,
        causation_id: None,
        command_id: [0x61; 16],
        idempotency_key: "frozen-replay-cursor".into(),
        actor: "runne-daemon".into(),
        integrity_digest: [0x62; 32],
        correlation_id: AGGREGATE,
        correlation_type: 2,
        integrity_profile: 1,
    }
}

pub fn fixture_scope() -> ReplayScope {
    ReplayScope::Aggregate {
        aggregate_type: 2,
        aggregate_id: AGGREGATE,
    }
}

pub fn encode_cursor(cursor: &ReplayCursor) -> String {
    format!(
        "gocode-replay-cursor-v1.{}",
        hex::encode(serde_json::to_vec(cursor).unwrap())
    )
}

pub fn aggregate_id_wire() -> String {
    uuid::Uuid::from_bytes(AGGREGATE).to_string()
}

pub fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(
            "authorization",
            session_authorization_header(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SESSION_AUTHORITY),
            )
            .unwrap(),
        )
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

pub async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

pub struct AllowAuthorization;
impl ReplayAuthorizationPort for AllowAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            request.expected_epoch,
            Sensitivity::Sensitive,
        )
    }
}

pub struct AllowContent;
impl ProhibitedContentPort for AllowContent {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

fn binding() -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            [
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1,
            ],
            ApiPrincipalId::new("local-owner").unwrap(),
            EventLogLineageId::from_bytes(LINEAGE),
            "gocode-ui-client/2",
            [0x31; 32],
            [0x41; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes([
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2,
        ]),
        7,
        AUTHORITY,
        0,
        Sensitivity::Sensitive,
        [0x51; 32],
    )
    .unwrap()
}

pub fn fixture_router(service: ReplayService) -> Router {
    let binding = binding();
    let mut sessions = LocalSessionService::new(binding.clone(), BOOTSTRAP_KEY);
    let challenge = sessions
        .issue_challenge([0x11; 32], [0x12; 32], std::time::Duration::ZERO)
        .unwrap();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&BOOTSTRAP_KEY).unwrap();
    mac.update(&bootstrap_proof_transcript(
        &binding, [0x12; 32], [0x11; 32],
    ));
    sessions
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            SESSION_AUTHORITY,
            std::time::Duration::ZERO,
        )
        .unwrap();
    let state = ReplayHttpState::new(
        service,
        ReplayHttpBinding::new(AUTHORITY, 7, 0).unwrap(),
        LimitsConfig::default(),
        Arc::new(AllowContent),
    );
    replay_router(state)
        .layer(SessionAuthLayer::new(
            Arc::new(Mutex::new(sessions)),
            binding,
            Arc::new(|| std::time::Duration::ZERO),
        ))
        .layer(axum::middleware::from_fn(request_id_middleware))
}
