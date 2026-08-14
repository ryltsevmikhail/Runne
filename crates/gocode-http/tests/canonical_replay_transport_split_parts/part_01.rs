use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use futures::StreamExt;
use gocode_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use gocode_application::local_session::AuthenticatedRuntimeSession;
use gocode_application::local_session::{
    BootstrapProof, LocalSessionService, bootstrap_proof_transcript,
};
use gocode_application::ports::{
    ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::replay_service::ReplayService;
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{
    AggregateId, CommandId, EventId, EventLogLineageId, IdempotencyKey, IntegrityDigest, TaskRunId,
};
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;
use gocode_http::auth::{SessionAuthLayer, session_authorization_header};
use gocode_http::limits::LimitsConfig;
use gocode_http::middleware::request_id_middleware;
use gocode_http::replay::{ReplayHttpBinding, ReplayHttpState, replay_router};
use gocode_store::codec::{StoreCodec, TaskRunEventCodec};
use gocode_store::integrity::compute_integrity_digest_with_global_position;
use gocode_store::schema::{
    apply_migrations, ensure_authority_id, ensure_exact_event_log_lineage_id, open_with_pragmas,
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use std::sync::Mutex;
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xAB; 32];
const SESSION_AUTHORITY: [u8; 32] = [0xAC; 32];
const AGGREGATE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0xbb,
];
const LINEAGE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0xcc,
];
const AUTHORITY: [u8; 16] = [0xAA; 16];
const GENERATION: i64 = 7;
const PROHIBITED_MARKER: &str = "task-seven-replay-marker";

fn aggregate_id_wire() -> String {
    uuid::Uuid::from_bytes(AGGREGATE).to_string()
}

fn authenticated_runtime_session() -> AuthenticatedRuntimeSession {
    AuthenticatedRuntimeSession {
        binding: RuntimeSessionBinding::new(
            StableRuntimeBinding::new(
                [
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0x01,
                ],
                ApiPrincipalId::new("local-owner").unwrap(),
                EventLogLineageId::from_bytes(LINEAGE),
                "gocode-ui-client/2",
                [0x31; 32],
                [0x41; 32],
            )
            .unwrap(),
            DaemonInstanceId::from_bytes([
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0x02,
            ]),
            u64::try_from(GENERATION).unwrap(),
            [
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0x03,
            ],
            0,
            Sensitivity::Sensitive,
            [0x51; 32],
        )
        .unwrap(),
        expires_at_monotonic: std::time::Duration::from_secs(600),
    }
}

fn session_auth_layer() -> SessionAuthLayer {
    let binding = authenticated_runtime_session().binding;
    let mut service = LocalSessionService::new(binding.clone(), TOKEN);
    let challenge = service
        .issue_challenge([0x11; 32], [0x12; 32], std::time::Duration::ZERO)
        .unwrap();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&TOKEN).unwrap();
    mac.update(&bootstrap_proof_transcript(
        &binding, [0x12; 32], [0x11; 32],
    ));
    service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            SESSION_AUTHORITY,
            std::time::Duration::ZERO,
        )
        .unwrap();
    SessionAuthLayer::new(
        Arc::new(Mutex::new(service)),
        binding,
        Arc::new(|| std::time::Duration::ZERO),
    )
}

struct AvailableGuard;

struct AvailableReplayAuthorization;

impl ReplayAuthorizationPort for AvailableReplayAuthorization {
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

impl ProhibitedContentPort for AvailableGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

enum DenyMode {
    Marker,
    Unavailable,
}

struct DenyGuard(DenyMode);

impl ProhibitedContentPort for DenyGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        match self.0 {
            DenyMode::Unavailable => Err(ContentGuardError::Unavailable),
            DenyMode::Marker
                if bytes
                    .windows(PROHIBITED_MARKER.len())
                    .any(|window| window == PROHIBITED_MARKER.as_bytes()) =>
            {
                Ok(ContentDisposition::Prohibited { policy_epoch: 2 })
            }
            DenyMode::Marker => Ok(ContentDisposition::Allowed { policy_epoch: 2 }),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum SwitchMode {
    Available = 0,
    Marker = 1,
    Unavailable = 2,
}

struct SwitchableGuard(AtomicU8);

impl SwitchableGuard {
    fn new(mode: SwitchMode) -> Self {
        Self(AtomicU8::new(mode as u8))
    }

    fn set(&self, mode: SwitchMode) {
        self.0.store(mode as u8, Ordering::SeqCst);
    }
}

impl ProhibitedContentPort for SwitchableGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        match self.0.load(Ordering::SeqCst) {
            value if value == SwitchMode::Available as u8 => {
                Ok(ContentDisposition::Allowed { policy_epoch: 1 })
            }
            value
                if value == SwitchMode::Marker as u8
                    && bytes
                        .windows(PROHIBITED_MARKER.len())
                        .any(|window| window == PROHIBITED_MARKER.as_bytes()) =>
            {
                Ok(ContentDisposition::Prohibited { policy_epoch: 2 })
            }
            value if value == SwitchMode::Marker as u8 => {
                Ok(ContentDisposition::Allowed { policy_epoch: 2 })
            }
            _ => Err(ContentGuardError::Unavailable),
        }
    }
}

struct TaskRunRow {
    event_id: [u8; 16],
    idempotency_key: Vec<u8>,
    payload: Vec<u8>,
    integrity_digest: [u8; 32],
}

fn event_id(global_position: i64) -> [u8; 16] {
    let mut bytes = [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0,
    ];
    bytes[14..].copy_from_slice(
        &u16::try_from(global_position)
            .expect("test position fits u16")
            .to_be_bytes(),
    );
    bytes
}

fn taskrun_row(sequence: i64, global_position: i64, key: String) -> TaskRunRow {
    taskrun_row_with_schema(sequence, global_position, key, 1)
}

fn taskrun_row_with_schema(
    sequence: i64,
    global_position: i64,
    key: String,
    schema_version: u32,
) -> TaskRunRow {
    let event_id_bytes = event_id(global_position);
    let taskrun_id = TaskRunId::from_bytes(AGGREGATE);
    let payload = if key.contains(PROHIBITED_MARKER) {
        TaskRunEvent::TaskRunFailed {
            reason: key.clone(),
        }
    } else {
        TaskRunEvent::TaskRunCreated
    };
    let idempotency_key = IdempotencyKey::new(key).unwrap();
    let payload_bytes = TaskRunEventCodec.encode(&payload).unwrap();
    let envelope = EventEnvelope::from_parts(
        EventId::from_bytes(event_id_bytes),
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        None,
        CommandId::from_bytes(event_id_bytes),
        idempotency_key.clone(),
        schema_version,
        Actor::new("test-actor").unwrap(),
        Sensitivity::Public,
        payload,
        u64::try_from(sequence).unwrap(),
        Timestamp::from_unix_micros(0),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let integrity_digest =
        compute_integrity_digest_with_global_position(&envelope, global_position, &payload_bytes)
            .unwrap()
            .into_bytes();
    TaskRunRow {
        event_id: event_id_bytes,
        idempotency_key: idempotency_key.as_str().as_bytes().to_vec(),
        payload: payload_bytes,
        integrity_digest,
    }
}

fn setup() -> (axum::Router, ReplayTestDatabase) {
    setup_with("replay-test", Arc::new(AvailableGuard))
}

fn setup_with(
    idempotency_key: &str,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
) -> (axum::Router, ReplayTestDatabase) {
    setup_with_events(vec![idempotency_key.to_owned()], prohibited_content)
}
