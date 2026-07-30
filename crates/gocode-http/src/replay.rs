//! Replay HTTP handlers — canonical replay session API.
//!
//! Six POST endpoints implement the ADR-0013 replay session lifecycle:
//! open-session, read-page, acknowledge, complete-catch-up, continue-live, close.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use gocode_api::{
    ApiReplayBindingId, ApiReplayBindingV1, ApiReplayEventSchema, CanonicalReplayPayloadV1,
    RetentionManifest as ApiRetentionManifest,
};
use gocode_application::local_session::AuthenticatedRuntimeSession;
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use gocode_application::replay_service::{
    ReplayDeliveryPrecommitGuard, ReplayError, ReplayEvent, ReplayService, ReplaySession,
};
use gocode_domain::replay::{ReplayCursor, ReplayScope};
use gocode_store::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::AuthenticatedPrincipal;
use crate::error::{RequestId, canonical_error_response};
use crate::limits::{
    LimitsConfig, MAX_ENCODED_REPLAY_PAGE_BYTES, MAX_LIVE_QUEUE_FRAMES, MAX_REPLAY_BODY_BYTES,
    MAX_REPLAY_PAGE_SIZE, ReplayCountPermit, ReplayQuotaManager,
};
use crate::sse::{
    SseDelivery, SseItem, SseSendError, SseSender, SseTerminalFrame, into_sse_stream,
    sse_channel_with_quota,
};

const MAX_CURSOR_TOKEN_BYTES: usize = 8 * 1024;
const CURSOR_TOKEN_PREFIX: &str = "gocode-replay-cursor-v1.";
const MAX_SSE_FRAME_BYTES: usize = 256 * 1024;
const LIVE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const SSE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// Immutable authority/generation lease for one daemon process.
#[derive(Clone, Copy, Debug)]
pub struct ReplayHttpBinding {
    authority_id: [u8; 16],
    session_generation: i64,
    authorization_epoch: i64,
}

impl ReplayHttpBinding {
    /// Validates the runtime authority and process generation bound into every
    /// replay operation.
    pub fn new(
        authority_id: [u8; 16],
        session_generation: i64,
        authorization_epoch: i64,
    ) -> Result<Self, ReplayHttpConfigurationError> {
        if authority_id == [0; 16] {
            return Err(ReplayHttpConfigurationError::EmptyAuthority);
        }
        if session_generation <= 0 {
            return Err(ReplayHttpConfigurationError::InvalidGeneration);
        }
        if authorization_epoch < 0 {
            return Err(ReplayHttpConfigurationError::InvalidAuthorizationEpoch);
        }
        Ok(Self {
            authority_id,
            session_generation,
            authorization_epoch,
        })
    }
}

/// Invalid daemon-owned replay transport configuration.
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum ReplayHttpConfigurationError {
    #[error("replay authority must not be empty")]
    EmptyAuthority,
    #[error("replay session generation must be positive")]
    InvalidGeneration,
    #[error("replay authorization epoch must not be negative")]
    InvalidAuthorizationEpoch,
}

/// Shared state for Replay HTTP handlers.
#[derive(Clone)]
pub struct ReplayHttpState {
    pub service: Arc<ReplayService>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    binding: ReplayHttpBinding,
    limits: LimitsConfig,
    active_page_reads: Arc<Mutex<HashSet<[u8; 16]>>>,
    active_drains: Arc<Mutex<HashSet<[u8; 16]>>>,
    quotas: ReplayQuotaManager,
    session_permits: Arc<Mutex<HashMap<[u8; 16], ReplayCountPermit>>>,
}

impl ReplayHttpState {
    pub fn new(
        service: ReplayService,
        binding: ReplayHttpBinding,
        limits: LimitsConfig,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Self {
        Self {
            service: Arc::new(service),
            prohibited_content,
            binding,
            limits,
            active_page_reads: Arc::new(Mutex::new(HashSet::new())),
            active_drains: Arc::new(Mutex::new(HashSet::new())),
            quotas: ReplayQuotaManager::default(),
            session_permits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn claim_page_read(&self, session_id: [u8; 16]) -> Option<SessionClaim> {
        SessionClaim::acquire(Arc::clone(&self.active_page_reads), session_id)
    }

    fn claim_live_drain(&self, session_id: [u8; 16]) -> Option<SessionClaim> {
        SessionClaim::acquire(Arc::clone(&self.active_drains), session_id)
    }

    fn retain_session_permit(
        &self,
        session_id: [u8; 16],
        permit: ReplayCountPermit,
    ) -> Result<(), ReplayHttpFailure> {
        let mut permits = self
            .session_permits
            .lock()
            .map_err(|_| replay_backpressure())?;
        if permits.insert(session_id, permit).is_some() {
            return Err(replay_invariant_violation());
        }
        Ok(())
    }

    fn take_session_permit(&self, session_id: &[u8; 16]) -> Option<ReplayCountPermit> {
        self.session_permits
            .lock()
            .ok()
            .and_then(|mut permits| permits.remove(session_id))
    }

    fn release_session_permit(&self, session_id: &[u8; 16]) {
        drop(self.take_session_permit(session_id));
    }

    fn release_session_permit_on_terminal_error(&self, session_id: &[u8; 16], error: &ReplayError) {
        if replay_error_terminates_session(error) {
            self.release_session_permit(session_id);
        }
    }
}

struct SessionClaim {
    sessions: Arc<Mutex<HashSet<[u8; 16]>>>,
    session_id: [u8; 16],
}

impl SessionClaim {
    fn acquire(sessions: Arc<Mutex<HashSet<[u8; 16]>>>, session_id: [u8; 16]) -> Option<Self> {
        let acquired = sessions
            .lock()
            .map(|mut sessions| sessions.insert(session_id))
            .unwrap_or(false);
        acquired.then_some(Self {
            sessions,
            session_id,
        })
    }
}

impl Drop for SessionClaim {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(&self.session_id);
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpenSessionRequest {
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub from_cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenSessionResponse {
    pub session_id: String,
    pub high_water_ref: String,
    pub events: Vec<DeliveredReplayEventWire>,
    pub has_more: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadPageRequest {
    pub limit: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadPageResponse {
    pub events: Vec<DeliveredReplayEventWire>,
    pub has_more: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcknowledgeRequest {
    pub cursor: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcknowledgeResponse {
    pub acknowledged: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CompleteCatchUpResponse {
    pub catch_up_proof: String,
    pub session_state: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContinueLiveResponse {
    pub live_delivery_id: String,
    pub session_state: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredReplayEventWire {
    pub event_id: String,
    pub aggregate_type: &'static str,
    pub aggregate_id: String,
    pub sequence: i64,
    pub timestamp_unix_micros: i64,
    pub sensitivity: &'static str,
    pub schema_version: u32,
    pub event_type: String,
    pub causation_event_id: Option<String>,
    pub integrity_digest: String,
    pub correlation_id: String,
    pub correlation_type: &'static str,
    pub payload: CanonicalReplayPayloadV1,
    pub replay_binding_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveredReplayEventWire {
    #[serde(flatten)]
    pub event: StoredReplayEventWire,
    pub cursor: String,
}

fn uuid_wire(bytes: &[u8; 16]) -> Result<String, ReplayHttpFailure> {
    let value = uuid::Uuid::from_bytes(*bytes);
    if value.get_version_num() != 7 || value.get_variant() != uuid::Variant::RFC4122 {
        return Err(replay_invariant_violation());
    }
    Ok(value.to_string())
}

#[derive(Clone, Copy, Debug)]
struct ReplayHttpFailure {
    status: StatusCode,
    code: &'static str,
}

impl ReplayHttpFailure {
    const fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }

    fn into_response(self, request_id: &RequestId) -> Response {
        canonical_error_response(self.status, self.code, request_id)
    }
}

fn encode_cursor(cursor: &ReplayCursor) -> Result<String, ReplayHttpFailure> {
    let bytes = serde_json::to_vec(cursor).map_err(|_| replay_invariant_violation())?;
    if bytes.len() > MAX_CURSOR_TOKEN_BYTES {
        return Err(replay_invariant_violation());
    }
    Ok(format!("{CURSOR_TOKEN_PREFIX}{}", hex::encode(bytes)))
}

fn decode_cursor(token: &str) -> Result<ReplayCursor, ReplayHttpFailure> {
    let encoded = token
        .strip_prefix(CURSOR_TOKEN_PREFIX)
        .ok_or_else(invalid_replay_cursor)?;
    if encoded.is_empty()
        || encoded.len() > MAX_CURSOR_TOKEN_BYTES.saturating_mul(2)
        || encoded.len() % 2 != 0
    {
        return Err(invalid_replay_cursor());
    }
    let bytes = hex::decode(encoded).map_err(|_| invalid_replay_cursor())?;
    serde_json::from_slice(&bytes).map_err(|_| invalid_replay_cursor())
}

fn canonical_payload(event: &ReplayEvent) -> Result<CanonicalReplayPayloadV1, ReplayHttpFailure> {
    if event.schema_version != 1 {
        return Err(replay_unsupported_schema());
    }
    match event.aggregate_type {
        1 => TaskRunEventCodec
            .decode(&event.payload)
            .map_err(|_| replay_unsupported_schema())
            .and_then(|event| {
                CanonicalReplayPayloadV1::try_from(&event).map_err(|_| replay_unsupported_schema())
            }),
        2 => ConversationEventCodec
            .decode(&event.payload)
            .map(|event| CanonicalReplayPayloadV1::from(&event))
            .map_err(|_| replay_unsupported_schema()),
        _ => Err(replay_invariant_violation()),
    }
}

fn binding_id(
    authenticated: &AuthenticatedRuntimeSession,
    session: &ReplaySession,
) -> Result<ApiReplayBindingId, ReplayHttpFailure> {
    let stable = authenticated.binding.stable();
    let ephemeral = authenticated.binding.ephemeral();
    let session_generation =
        u64::try_from(session.session_generation).map_err(|_| replay_invariant_violation())?;
    let authorization_epoch =
        u64::try_from(session.authorization_epoch).map_err(|_| replay_invariant_violation())?;
    if stable.principal_id().as_str() != session.principal_id
        || ephemeral.launch_generation() != session_generation
        || ephemeral.authorization_epoch() != authorization_epoch
    {
        return Err(replay_authorization_revoked());
    }
    let mut digest = Sha256::new();
    digest.update(b"gocode/api-replay-binding/v1\0");
    digest.update(stable.authority_id());
    digest.update(stable.principal_id().as_str().as_bytes());
    digest.update(stable.lineage_id().as_bytes());
    digest.update(stable.profile_id().as_bytes());
    digest.update(stable.schema_hash());
    digest.update(stable.capability_digest());
    digest.update(ephemeral.daemon_instance_id().into_bytes());
    digest.update(ephemeral.launch_generation().to_be_bytes());
    digest.update(ephemeral.session_id());
    digest.update(ephemeral.authorization_epoch().to_be_bytes());
    digest.update(authenticated.binding.certificate_sha256());
    digest.update(session.session_id);
    digest.update(session.retention_generation.to_be_bytes());
    digest.update(&session.high_water_ref);
    let bytes: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&bytes[..16]);
    ApiReplayBindingId::new(id).map_err(|_| replay_invariant_violation())
}

fn validate_api_binding(
    authenticated: &AuthenticatedRuntimeSession,
    session: &ReplaySession,
    event_type: &str,
    binding_id: ApiReplayBindingId,
) -> Result<(), ReplayHttpFailure> {
    let authorization_epoch =
        u64::try_from(session.authorization_epoch).map_err(|_| replay_invariant_violation())?;
    let public_retention_generation = u64::try_from(session.retention_generation)
        .ok()
        .and_then(|generation| generation.checked_add(1))
        .ok_or_else(replay_invariant_violation)?;
    let retention_digest: [u8; 32] = Sha256::digest(&session.high_water_ref).into();
    let retention_manifest =
        ApiRetentionManifest::new(public_retention_generation, retention_digest)
            .map_err(|_| replay_invariant_violation())?;
    let schema =
        ApiReplayEventSchema::new(event_type, 1).map_err(|_| replay_unsupported_schema())?;
    ApiReplayBindingV1::new(
        binding_id,
        authenticated.binding.clone(),
        authorization_epoch,
        authenticated.binding.ephemeral().sensitivity_ceiling(),
        [schema],
        session.session_id,
        retention_manifest,
    )
    .map_err(|_| replay_authorization_revoked())?;
    Ok(())
}

fn wire_event(
    authenticated: &AuthenticatedRuntimeSession,
    session: &ReplaySession,
    event: &ReplayEvent,
) -> Result<StoredReplayEventWire, ReplayHttpFailure> {
    let sensitivity = match event.sensitivity {
        0 => "public",
        1 => "internal",
        2 => "sensitive",
        _ => return Err(replay_invariant_violation()),
    };
    let aggregate_type = match event.aggregate_type {
        1 => "taskRun",
        2 => "conversation",
        _ => return Err(replay_invariant_violation()),
    };
    let correlation_type = match event.correlation_type {
        1 => "taskRun",
        2 => "conversation",
        _ => return Err(replay_invariant_violation()),
    };
    let payload = canonical_payload(event)?;
    let payload_value = serde_json::to_value(&payload).map_err(|_| replay_invariant_violation())?;
    let event_type = payload_value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(replay_unsupported_schema)?
        .to_owned();
    let binding_id = binding_id(authenticated, session)?;
    validate_api_binding(authenticated, session, &event_type, binding_id)?;
    Ok(StoredReplayEventWire {
        event_id: uuid_wire(&event.event_id)?,
        aggregate_type,
        aggregate_id: uuid_wire(&event.aggregate_id)?,
        sequence: event.sequence,
        timestamp_unix_micros: event.timestamp,
        sensitivity,
        schema_version: event.schema_version,
        event_type,
        causation_event_id: event.causation_id.as_ref().map(uuid_wire).transpose()?,
        integrity_digest: hex::encode(event.integrity_digest),
        correlation_id: uuid_wire(&event.correlation_id)?,
        correlation_type,
        payload,
        replay_binding_id: binding_id.to_wire_value(),
    })
}

fn wire_delivery(
    authenticated: &AuthenticatedRuntimeSession,
    session: &ReplaySession,
    event: &ReplayEvent,
    cursor: &ReplayCursor,
) -> Result<DeliveredReplayEventWire, ReplayHttpFailure> {
    Ok(DeliveredReplayEventWire {
        event: wire_event(authenticated, session, event)?,
        cursor: encode_cursor(cursor)?,
    })
}

fn inspect_replay_bytes(
    prohibited_content: &dyn ProhibitedContentPort,
    bytes: &[u8],
) -> Result<(), ReplayError> {
    match prohibited_content.inspect(CanonicalContentBoundary::OutboundDelivery, bytes) {
        Ok(ContentDisposition::Allowed { .. }) => Ok(()),
        Ok(ContentDisposition::Prohibited { .. }) | Err(_) => Err(ReplayError::SensitivityDenied),
    }
}

fn replay_delivery_integrity_error() -> ReplayError {
    ReplayError::Integrity("replay delivery encoding failed".to_owned())
}

fn wire_deliveries(
    authenticated: &AuthenticatedRuntimeSession,
    service: &ReplayService,
    session: &ReplaySession,
    events: &[ReplayEvent],
) -> Result<Vec<DeliveredReplayEventWire>, ReplayHttpFailure> {
    let scope = ReplayScope::Aggregate {
        aggregate_type: u8::try_from(session.aggregate_type)
            .map_err(|_| replay_invariant_violation())?,
        aggregate_id: session.aggregate_id,
    };
    events
        .iter()
        .map(|event| {
            let cursor = service
                .build_cursor_from_event(event, &scope)
                .map_err(|_| replay_invariant_violation())?;
            wire_delivery(authenticated, session, event, &cursor)
        })
        .collect()
}

fn open_session_response(
    authenticated: &AuthenticatedRuntimeSession,
    service: &ReplayService,
    session: &ReplaySession,
    events: &[ReplayEvent],
) -> Result<OpenSessionResponse, ReplayHttpFailure> {
    Ok(OpenSessionResponse {
        session_id: session_id_hex(&session.session_id),
        high_water_ref: high_water_ref_hex(&session.high_water_ref),
        events: wire_deliveries(authenticated, service, session, events)?,
        has_more: session.next_page_position.is_some(),
    })
}

fn read_page_response(
    authenticated: &AuthenticatedRuntimeSession,
    service: &ReplayService,
    session: &ReplaySession,
    events: &[ReplayEvent],
) -> Result<ReadPageResponse, ReplayHttpFailure> {
    Ok(ReadPageResponse {
        events: wire_deliveries(authenticated, service, session, events)?,
        has_more: session.next_page_position.is_some(),
    })
}

struct OpenSessionDeliveryGuard {
    authenticated: AuthenticatedRuntimeSession,
    service: Arc<ReplayService>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

impl ReplayDeliveryPrecommitGuard for OpenSessionDeliveryGuard {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError> {
        let response =
            open_session_response(&self.authenticated, self.service.as_ref(), session, events)
                .map_err(replay_http_failure_to_delivery_error)?;
        let bytes = serde_json::to_vec(&response).map_err(|_| replay_delivery_integrity_error())?;
        if bytes.len() > MAX_ENCODED_REPLAY_PAGE_BYTES {
            return Err(ReplayError::BackpressureExceeded);
        }
        inspect_replay_bytes(self.prohibited_content.as_ref(), &bytes)
    }
}

struct ReadPageDeliveryGuard {
    authenticated: AuthenticatedRuntimeSession,
    service: Arc<ReplayService>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

impl ReplayDeliveryPrecommitGuard for ReadPageDeliveryGuard {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError> {
        let response =
            read_page_response(&self.authenticated, self.service.as_ref(), session, events)
                .map_err(replay_http_failure_to_delivery_error)?;
        let bytes = serde_json::to_vec(&response).map_err(|_| replay_delivery_integrity_error())?;
        if bytes.len() > MAX_ENCODED_REPLAY_PAGE_BYTES {
            return Err(ReplayError::BackpressureExceeded);
        }
        inspect_replay_bytes(self.prohibited_content.as_ref(), &bytes)
    }
}

fn session_id_hex(id: &[u8; 16]) -> String {
    hex::encode(id)
}

fn high_water_ref_hex(high_water_ref: &[u8]) -> String {
    hex::encode(high_water_ref)
}

fn live_delivery_id_wire(value: &[u8]) -> Result<String, ReplayHttpFailure> {
    if value.len() != 16 {
        return Err(replay_invariant_violation());
    }
    let digest = Sha256::digest([b"gocode/live-delivery-id/v1\0".as_slice(), value].concat());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}

fn parse_aggregate_id(hex_id: &str) -> Result<[u8; 16], ReplayHttpFailure> {
    let id = uuid::Uuid::parse_str(hex_id)
        .map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_aggregate_id"))?;
    if id.get_version_num() != 7 || id.get_variant() != uuid::Variant::RFC4122 {
        return Err(ReplayHttpFailure::new(
            StatusCode::BAD_REQUEST,
            "invalid_aggregate_id",
        ));
    }
    Ok(*id.as_bytes())
}

fn extract_session_id(session_id: &str) -> Result<[u8; 16], ReplayHttpFailure> {
    let bytes = hex::decode(session_id).map_err(|_| {
        ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_replay_session_id")
    })?;
    bytes
        .try_into()
        .map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_replay_session_id"))
}

fn invalid_replay_cursor() -> ReplayHttpFailure {
    ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_replay_cursor")
}

fn replay_invariant_violation() -> ReplayHttpFailure {
    ReplayHttpFailure::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "runtime_invariant_violation",
    )
}

fn replay_unsupported_schema() -> ReplayHttpFailure {
    ReplayHttpFailure::new(StatusCode::CONFLICT, "replay_unsupported_schema")
}

fn replay_authorization_revoked() -> ReplayHttpFailure {
    ReplayHttpFailure::new(StatusCode::UNAUTHORIZED, "replay_authorization_revoked")
}

fn replay_backpressure() -> ReplayHttpFailure {
    ReplayHttpFailure::new(StatusCode::TOO_MANY_REQUESTS, "replay_backpressure")
}

fn map_json_rejection(rejection: JsonRejection) -> ReplayHttpFailure {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ReplayHttpFailure::new(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large")
    } else {
        ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request")
    }
}

fn replay_http_failure_to_delivery_error(error: ReplayHttpFailure) -> ReplayError {
    match error.code {
        "replay_unsupported_schema" => {
            ReplayError::Integrity("unsupported replay schema".to_owned())
        }
        "replay_authorization_revoked" => ReplayError::AuthorizationRevoked,
        "replay_backpressure" => ReplayError::BackpressureExceeded,
        _ => replay_delivery_integrity_error(),
    }
}

fn replay_error_to_http(error: &ReplayError) -> ReplayHttpFailure {
    match error {
        ReplayError::SessionNotFound => {
            ReplayHttpFailure::new(StatusCode::NOT_FOUND, "replay_session_not_found")
        }
        ReplayError::Unauthorized(_) => {
            ReplayHttpFailure::new(StatusCode::UNAUTHORIZED, "unauthorized")
        }
        ReplayError::AuthorizationRevoked => replay_authorization_revoked(),
        ReplayError::InvalidState(_) | ReplayError::NotAcknowledged => {
            ReplayHttpFailure::new(StatusCode::CONFLICT, "replay_session_conflict")
        }
        ReplayError::AlreadyAcknowledged => {
            ReplayHttpFailure::new(StatusCode::CONFLICT, "replay_cursor_regression")
        }
        ReplayError::StaleGeneration | ReplayError::StreamTerminated => {
            ReplayHttpFailure::new(StatusCode::GONE, "replay_session_expired")
        }
        ReplayError::ReplayRetentionGap { .. } => {
            ReplayHttpFailure::new(StatusCode::GONE, "replay_retention_gap")
        }
        ReplayError::Storage(_) => {
            ReplayHttpFailure::new(StatusCode::SERVICE_UNAVAILABLE, "runtime_unavailable")
        }
        ReplayError::Integrity(message) if message == "unsupported replay schema" => {
            replay_unsupported_schema()
        }
        ReplayError::Integrity(_) => replay_invariant_violation(),
        ReplayError::CursorInvalid { .. } => invalid_replay_cursor(),
        ReplayError::SensitivityDenied => {
            ReplayHttpFailure::new(StatusCode::FORBIDDEN, "replay_sensitivity_denied")
        }
        ReplayError::BackpressureExceeded => replay_backpressure(),
    }
}

fn replay_error_terminates_session(error: &ReplayError) -> bool {
    matches!(
        error,
        ReplayError::SessionNotFound
            | ReplayError::AuthorizationRevoked
            | ReplayError::StaleGeneration
            | ReplayError::ReplayRetentionGap { .. }
            | ReplayError::Integrity(_)
            | ReplayError::StreamTerminated
    )
}

async fn open_session(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(authenticated): Extension<AuthenticatedRuntimeSession>,
    Extension(request_id): Extension<RequestId>,
    body: Result<Json<OpenSessionRequest>, JsonRejection>,
) -> Response {
    let result: Result<OpenSessionResponse, ReplayHttpFailure> = async {
        let Json(req) = body.map_err(map_json_rejection)?;
        let aggregate_id = parse_aggregate_id(&req.aggregate_id)?;
        let aggregate_type = match req.aggregate_type.as_str() {
            "taskRun" => 1,
            "conversation" => 2,
            _ => {
                return Err(ReplayHttpFailure::new(
                    StatusCode::BAD_REQUEST,
                    "unsupported_replay_scope",
                ));
            }
        };
        let session_permit = state
            .quotas
            .reserve_session(principal.as_api_principal().as_str())
            .map_err(|_| replay_backpressure())?;
        if authenticated.binding.stable().principal_id() != principal.as_api_principal() {
            return Err(replay_authorization_revoked());
        }
        let from_cursor = req.from_cursor.as_deref().map(decode_cursor).transpose()?;
        let delivery_guard = Arc::new(OpenSessionDeliveryGuard {
            authenticated: authenticated.clone(),
            service: Arc::clone(&state.service),
            prohibited_content: Arc::clone(&state.prohibited_content),
        });
        let (session, events) = state
            .service
            .open_session(
                principal.as_api_principal().as_str(),
                state.binding.session_generation,
                &state.binding.authority_id,
                state.binding.authorization_epoch,
                aggregate_type,
                &aggregate_id,
                from_cursor,
                delivery_guard,
            )
            .await
            .map_err(|error| replay_error_to_http(&error))?;
        let response =
            open_session_response(&authenticated, state.service.as_ref(), &session, &events)?;
        state.retain_session_permit(session.session_id, session_permit)?;
        Ok(response)
    }
    .await;

    match result {
        Ok(response) => bounded_json_response(StatusCode::OK, &response)
            .unwrap_or_else(|error| error.into_response(&request_id)),
        Err(error) => error.into_response(&request_id),
    }
}

async fn read_page(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(authenticated): Extension<AuthenticatedRuntimeSession>,
    Extension(request_id): Extension<RequestId>,
    Path(session_hex): Path<String>,
    body: Result<Json<ReadPageRequest>, JsonRejection>,
) -> Response {
    let result: Result<ReadPageResponse, ReplayHttpFailure> = async {
        let Json(req) = body.map_err(map_json_rejection)?;
        let session_id = extract_session_id(&session_hex)?;
        let page_maximum = state.limits.max_page_size.min(MAX_REPLAY_PAGE_SIZE);
        let limit = req
            .limit
            .unwrap_or(state.limits.default_page_size.min(page_maximum));
        if limit == 0 || limit > page_maximum {
            return Err(ReplayHttpFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_replay_page_limit",
            ));
        }
        let _page_claim = state.claim_page_read(session_id).ok_or_else(|| {
            ReplayHttpFailure::new(StatusCode::CONFLICT, "replay_page_in_progress")
        })?;
        let delivery_guard = Arc::new(ReadPageDeliveryGuard {
            authenticated: authenticated.clone(),
            service: Arc::clone(&state.service),
            prohibited_content: Arc::clone(&state.prohibited_content),
        });
        let (session, events) = state
            .service
            .read_page(
                &session_id,
                principal.as_api_principal().as_str(),
                state.binding.session_generation,
                &state.binding.authority_id,
                state.binding.authorization_epoch,
                limit,
                delivery_guard,
            )
            .await
            .map_err(|error| {
                state.release_session_permit_on_terminal_error(&session_id, &error);
                replay_error_to_http(&error)
            })?;

        read_page_response(&authenticated, state.service.as_ref(), &session, &events)
    }
    .await;

    match result {
        Ok(response) => bounded_json_response(StatusCode::OK, &response)
            .unwrap_or_else(|error| error.into_response(&request_id)),
        Err(error) => error.into_response(&request_id),
    }
}

async fn acknowledge(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(_authenticated): Extension<AuthenticatedRuntimeSession>,
    Extension(request_id): Extension<RequestId>,
    Path(session_hex): Path<String>,
    body: Result<Json<AcknowledgeRequest>, JsonRejection>,
) -> Response {
    let result: Result<AcknowledgeResponse, ReplayHttpFailure> = async {
        let Json(req) = body.map_err(map_json_rejection)?;
        let session_id = extract_session_id(&session_hex)?;
        let cursor = decode_cursor(&req.cursor)?;
        state
            .service
            .acknowledge(
                &session_id,
                principal.as_api_principal().as_str(),
                state.binding.session_generation,
                &state.binding.authority_id,
                state.binding.authorization_epoch,
                &cursor,
            )
            .await
            .map_err(|error| {
                state.release_session_permit_on_terminal_error(&session_id, &error);
                replay_error_to_http(&error)
            })?;
        Ok(AcknowledgeResponse { acknowledged: true })
    }
    .await;

    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => error.into_response(&request_id),
    }
}

async fn complete_catch_up(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(_authenticated): Extension<AuthenticatedRuntimeSession>,
    Extension(request_id): Extension<RequestId>,
    Path(session_hex): Path<String>,
) -> Response {
    let result: Result<CompleteCatchUpResponse, ReplayHttpFailure> = async {
        let session_id = extract_session_id(&session_hex)?;
        let completion = state
            .service
            .complete_catch_up(
                &session_id,
                principal.as_api_principal().as_str(),
                state.binding.session_generation,
                &state.binding.authority_id,
                state.binding.authorization_epoch,
            )
            .await
            .map_err(|error| {
                state.release_session_permit_on_terminal_error(&session_id, &error);
                replay_error_to_http(&error)
            })?;
        Ok(CompleteCatchUpResponse {
            catch_up_proof: hex::encode(completion.proof.as_bytes()),
            session_state: "catch_up_complete".into(),
        })
    }
    .await;

    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => error.into_response(&request_id),
    }
}

async fn continue_live(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(_authenticated): Extension<AuthenticatedRuntimeSession>,
    Extension(request_id): Extension<RequestId>,
    Path(session_hex): Path<String>,
) -> Response {
    let result: Result<ContinueLiveResponse, ReplayHttpFailure> = async {
        let session_id = extract_session_id(&session_hex)?;
        let session = state
            .service
            .continue_live(
                &session_id,
                principal.as_api_principal().as_str(),
                state.binding.session_generation,
                &state.binding.authority_id,
                state.binding.authorization_epoch,
            )
            .await
            .map_err(|error| {
                state.release_session_permit_on_terminal_error(&session_id, &error);
                replay_error_to_http(&error)
            })?;
        let live_delivery_id = session
            .live_delivery_id
            .as_deref()
            .map(live_delivery_id_wire)
            .transpose()?
            .ok_or_else(replay_invariant_violation)?;
        Ok(ContinueLiveResponse {
            live_delivery_id,
            session_state: "live".into(),
        })
    }
    .await;

    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => error.into_response(&request_id),
    }
}

async fn close_session(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(_authenticated): Extension<AuthenticatedRuntimeSession>,
    Extension(request_id): Extension<RequestId>,
    Path(session_hex): Path<String>,
) -> Response {
    let result: Result<(), ReplayHttpFailure> = async {
        let session_id = extract_session_id(&session_hex)?;
        state
            .service
            .close_session(
                &session_id,
                principal.as_api_principal().as_str(),
                state.binding.session_generation,
                &state.binding.authority_id,
                state.binding.authorization_epoch,
            )
            .await
            .map_err(|error| {
                state.release_session_permit_on_terminal_error(&session_id, &error);
                replay_error_to_http(&error)
            })
    }
    .await;

    match result {
        Ok(()) => {
            if let Ok(session_id) = extract_session_id(&session_hex) {
                state.release_session_permit(&session_id);
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => error.into_response(&request_id),
    }
}

fn bounded_json_response<T: Serialize>(
    status: StatusCode,
    response: &T,
) -> Result<Response, ReplayHttpFailure> {
    let bytes = serde_json::to_vec(response).map_err(|_| replay_invariant_violation())?;
    if bytes.len() > MAX_ENCODED_REPLAY_PAGE_BYTES {
        return Err(replay_backpressure());
    }
    Ok((
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}

fn terminal(code: &'static str) -> SseItem {
    SseItem::Terminal(SseTerminalFrame {
        transport_version: 1,
        code: code.to_owned(),
    })
}

fn try_terminal(sender: &SseSender, code: &'static str) {
    let _ = sender.try_send(terminal(code));
}

fn live_delivery(
    authenticated: &AuthenticatedRuntimeSession,
    service: &ReplayService,
    session: &ReplaySession,
    event: &ReplayEvent,
    delivery_sequence: u64,
) -> Result<SseDelivery, ReplayHttpFailure> {
    if event.aggregate_type != session.aggregate_type
        || event.aggregate_id != session.aggregate_id
        || !matches!(event.sensitivity, 0..=2)
        || event.schema_version != 1
    {
        return Err(replay_invariant_violation());
    }
    let aggregate_type =
        u8::try_from(session.aggregate_type).map_err(|_| replay_invariant_violation())?;
    let cursor = service
        .build_cursor_from_event(
            event,
            &ReplayScope::Aggregate {
                aggregate_type,
                aggregate_id: session.aggregate_id,
            },
        )
        .map_err(|_| replay_invariant_violation())?;
    let replay_cursor = encode_cursor(&cursor)?;
    let canonical_event = serde_json::to_value(wire_event(authenticated, session, event)?)
        .map_err(|_| replay_invariant_violation())?;
    let live_delivery_id = session
        .live_delivery_id
        .as_deref()
        .map(live_delivery_id_wire)
        .transpose()?
        .ok_or_else(replay_invariant_violation)?;
    Ok(SseDelivery {
        transport_version: 1,
        replay_session_id: session_id_hex(&session.session_id),
        live_delivery_id: Some(live_delivery_id),
        delivery_sequence,
        canonical_event,
        replay_cursor,
    })
}

struct LiveDeliveryGuard {
    authenticated: AuthenticatedRuntimeSession,
    service: Arc<ReplayService>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    first_delivery_sequence: u64,
}

impl ReplayDeliveryPrecommitGuard for LiveDeliveryGuard {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError> {
        for (index, event) in events.iter().enumerate() {
            let sequence_offset =
                u64::try_from(index).map_err(|_| ReplayError::BackpressureExceeded)?;
            let delivery_sequence = self
                .first_delivery_sequence
                .checked_add(sequence_offset)
                .ok_or(ReplayError::BackpressureExceeded)?;
            let delivery = live_delivery(
                &self.authenticated,
                self.service.as_ref(),
                session,
                event,
                delivery_sequence,
            )
            .map_err(replay_http_failure_to_delivery_error)?;
            let bytes =
                serde_json::to_vec(&delivery).map_err(|_| replay_delivery_integrity_error())?;
            if bytes.len() > MAX_SSE_FRAME_BYTES {
                return Err(ReplayError::BackpressureExceeded);
            }
            inspect_replay_bytes(self.prohibited_content.as_ref(), &bytes)?;
        }
        Ok(())
    }
}

fn live_delivery_guard(
    state: &ReplayHttpState,
    authenticated: &AuthenticatedRuntimeSession,
    first_delivery_sequence: u64,
) -> Arc<dyn ReplayDeliveryPrecommitGuard> {
    Arc::new(LiveDeliveryGuard {
        authenticated: authenticated.clone(),
        service: Arc::clone(&state.service),
        prohibited_content: Arc::clone(&state.prohibited_content),
        first_delivery_sequence,
    })
}

struct LiveProducer {
    state: ReplayHttpState,
    session_id: [u8; 16],
    principal_id: String,
    authenticated: AuthenticatedRuntimeSession,
    sender: SseSender,
    _session_permit: ReplayCountPermit,
    _live_permit: ReplayCountPermit,
    _drain_claim: SessionClaim,
}

async fn produce_live_events(
    producer: LiveProducer,
    mut session: gocode_application::replay_service::ReplaySession,
    mut events: Vec<ReplayEvent>,
) {
    let LiveProducer {
        state,
        session_id,
        principal_id,
        authenticated,
        sender,
        _session_permit,
        _live_permit,
        _drain_claim,
    } = producer;
    let mut delivery_sequence = 1_u64;
    let mut stop = false;

    while !stop && !sender.is_closed() {
        for event in events.drain(..) {
            let delivery = match live_delivery(
                &authenticated,
                state.service.as_ref(),
                &session,
                &event,
                delivery_sequence,
            ) {
                Ok(delivery) => delivery,
                Err(error) => {
                    try_terminal(&sender, error.code);
                    stop = true;
                    break;
                }
            };
            let delivery_bytes = match serde_json::to_vec(&delivery) {
                Ok(bytes) => bytes,
                Err(_) => {
                    try_terminal(&sender, "runtime_invariant_violation");
                    stop = true;
                    break;
                }
            };
            let frame_size = delivery_bytes.len();
            if frame_size > MAX_SSE_FRAME_BYTES {
                try_terminal(&sender, "replay_backpressure");
                stop = true;
                break;
            }
            match sender.try_send(SseItem::Delivery(delivery)) {
                Ok(()) => {
                    delivery_sequence = match delivery_sequence.checked_add(1) {
                        Some(next) => next,
                        None => {
                            try_terminal(&sender, "replay_backpressure");
                            stop = true;
                            break;
                        }
                    };
                }
                Err(SseSendError::Backpressure) => {
                    try_terminal(&sender, "replay_backpressure");
                    stop = true;
                    break;
                }
                Err(SseSendError::Closed) => {
                    stop = true;
                    break;
                }
            }
        }

        if stop || sender.is_closed() {
            break;
        }
        tokio::time::sleep(LIVE_POLL_INTERVAL).await;
        match state
            .service
            .poll_live(
                &session_id,
                &principal_id,
                state.binding.session_generation,
                &state.binding.authority_id,
                state.binding.authorization_epoch,
                live_delivery_guard(&state, &authenticated, delivery_sequence),
            )
            .await
        {
            Ok((next_session, next_events)) => {
                session = next_session;
                events = next_events;
            }
            Err(
                ReplayError::Unauthorized(_)
                | ReplayError::StaleGeneration
                | ReplayError::StreamTerminated
                | ReplayError::SessionNotFound,
            ) => {
                try_terminal(&sender, "replay_session_expired");
                break;
            }
            Err(ReplayError::AuthorizationRevoked) => {
                try_terminal(&sender, "replay_authorization_revoked");
                break;
            }
            Err(ReplayError::SensitivityDenied) => {
                try_terminal(&sender, "replay_sensitivity_denied");
                break;
            }
            Err(ReplayError::ReplayRetentionGap { .. }) => {
                try_terminal(&sender, "replay_retention_gap");
                break;
            }
            Err(ReplayError::Integrity(message)) if message == "unsupported replay schema" => {
                try_terminal(&sender, "replay_unsupported_schema");
                break;
            }
            Err(ReplayError::BackpressureExceeded) => {
                try_terminal(&sender, "replay_backpressure");
                break;
            }
            Err(_) => {
                try_terminal(&sender, "runtime_invariant_violation");
                break;
            }
        }
    }

    let _ = state
        .service
        .close_session(
            &session_id,
            &principal_id,
            state.binding.session_generation,
            &state.binding.authority_id,
            state.binding.authorization_epoch,
        )
        .await;
}

async fn stream_live(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(authenticated): Extension<AuthenticatedRuntimeSession>,
    Extension(request_id): Extension<RequestId>,
    Path(session_hex): Path<String>,
) -> Response {
    let session_id = match extract_session_id(&session_hex) {
        Ok(session_id) => session_id,
        Err(error) => return error.into_response(&request_id),
    };
    let drain_claim = match state.claim_live_drain(session_id) {
        Some(claim) => claim,
        None => {
            return ReplayHttpFailure::new(StatusCode::CONFLICT, "replay_session_conflict")
                .into_response(&request_id);
        }
    };
    let principal_id = principal.as_api_principal().as_str().to_owned();
    let live_permit = match state.quotas.reserve_live(&principal_id) {
        Ok(permit) => permit,
        Err(_) => return replay_backpressure().into_response(&request_id),
    };
    let initial = state
        .service
        .poll_live(
            &session_id,
            &principal_id,
            state.binding.session_generation,
            &state.binding.authority_id,
            state.binding.authorization_epoch,
            live_delivery_guard(&state, &authenticated, 1),
        )
        .await;
    let (session, events) = match initial {
        Ok(initial) => initial,
        Err(error) => {
            state.release_session_permit_on_terminal_error(&session_id, &error);
            return replay_error_to_http(&error).into_response(&request_id);
        }
    };
    let session_permit = match state.take_session_permit(&session_id) {
        Some(permit) => permit,
        None => return replay_backpressure().into_response(&request_id),
    };
    let (sender, receiver) = sse_channel_with_quota(MAX_LIVE_QUEUE_FRAMES, state.quotas.queue());
    tokio::spawn(produce_live_events(
        LiveProducer {
            state,
            session_id,
            principal_id,
            authenticated,
            sender,
            _session_permit: session_permit,
            _live_permit: live_permit,
            _drain_claim: drain_claim,
        },
        session,
        events,
    ));
    into_sse_stream(receiver, SSE_HEARTBEAT_INTERVAL).into_response()
}

/// Builds the replay session control API router.
pub fn replay_router(state: ReplayHttpState) -> Router {
    let body_limit = state.limits.max_body_size.min(MAX_REPLAY_BODY_BYTES);
    Router::new()
        .route("/v1/replay/open-session", post(open_session))
        .route("/v1/replay/{session_id}/read-page", post(read_page))
        .route("/v1/replay/{session_id}/acknowledge", post(acknowledge))
        .route(
            "/v1/replay/{session_id}/complete-catch-up",
            post(complete_catch_up),
        )
        .route("/v1/replay/{session_id}/continue-live", post(continue_live))
        .route("/v1/replay/{session_id}/events", get(stream_live))
        .route("/v1/replay/{session_id}/close", post(close_session))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gocode_api::{
        ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding,
    };
    use gocode_application::local_session::AuthenticatedRuntimeSession;
    use gocode_application::replay_service::{
        ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayState,
    };
    use gocode_domain::event::Sensitivity;
    use gocode_domain::id::{EventLogLineageId, IntegrityDigest};
    use gocode_domain::replay::GapRangeRef;
    use gocode_store::replay_store::ReplayStore;

    struct AvailableReplayAuthorization;

    fn uuid_v7(last: u8) -> [u8; 16] {
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, last,
        ]
    }

    fn authenticated_runtime_session(session: &ReplaySession) -> AuthenticatedRuntimeSession {
        AuthenticatedRuntimeSession {
            binding: RuntimeSessionBinding::new(
                StableRuntimeBinding::new(
                    uuid_v7(1),
                    ApiPrincipalId::new(session.principal_id.clone()).unwrap(),
                    EventLogLineageId::from_bytes(uuid_v7(2)),
                    "gocode-ui-client/1",
                    [3; 32],
                    [4; 32],
                )
                .unwrap(),
                DaemonInstanceId::from_bytes(uuid_v7(5)),
                u64::try_from(session.session_generation).unwrap(),
                uuid_v7(6),
                u64::try_from(session.authorization_epoch).unwrap(),
                Sensitivity::Sensitive,
                [7; 32],
            )
            .unwrap(),
            expires_at_monotonic: Duration::from_secs(600),
        }
    }

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

    #[test]
    fn page_claim_is_exclusive_and_released_on_drop() {
        let sessions = Arc::new(Mutex::new(HashSet::new()));
        let session_id = [0x42; 16];

        let first = SessionClaim::acquire(Arc::clone(&sessions), session_id).unwrap();
        assert!(SessionClaim::acquire(Arc::clone(&sessions), session_id).is_none());
        drop(first);
        assert!(SessionClaim::acquire(sessions, session_id).is_some());
    }

    #[test]
    fn replay_failures_map_to_the_closed_public_codes() {
        let retention_gap = ReplayError::ReplayRetentionGap {
            floor_cursor: None,
            gap_range_ref: GapRangeRef::new(IntegrityDigest::from_bytes([9; 32])).unwrap(),
        };
        for (error, code) in [
            (ReplayError::StaleGeneration, "replay_session_expired"),
            (
                ReplayError::AuthorizationRevoked,
                "replay_authorization_revoked",
            ),
            (ReplayError::SensitivityDenied, "replay_sensitivity_denied"),
            (
                ReplayError::Integrity("unsupported replay schema".to_owned()),
                "replay_unsupported_schema",
            ),
            (retention_gap, "replay_retention_gap"),
            (ReplayError::BackpressureExceeded, "replay_backpressure"),
            (
                ReplayError::Integrity("invalid stored digest".to_owned()),
                "runtime_invariant_violation",
            ),
        ] {
            assert_eq!(replay_error_to_http(&error).code, code);
        }
    }

    #[test]
    fn oversized_serialized_page_is_rejected_before_response_creation() {
        let error =
            bounded_json_response(StatusCode::OK, &"x".repeat(MAX_ENCODED_REPLAY_PAGE_BYTES))
                .unwrap_err();

        assert_eq!(error.code, "replay_backpressure");
    }

    #[test]
    fn maximum_canonical_failure_payload_fits_sse_frame_limit() {
        let service = ReplayService::new(
            Arc::new(ReplayStore::new(
                rusqlite::Connection::open_in_memory().unwrap(),
            )),
            [0x11; 32],
            EventLogLineageId::from_bytes([0x22; 16]),
            Arc::new(AvailableReplayAuthorization),
        );
        let session = ReplaySession {
            session_id: uuid_v7(0x33),
            principal_id: "principal".to_owned(),
            session_generation: i64::MAX,
            authority_id: uuid_v7(0x44),
            authorization_epoch: i64::MAX,
            aggregate_type: 1,
            aggregate_id: uuid_v7(0x55),
            retained_floor: Some(1),
            retention_generation: 0,
            high_water_position: i64::MAX,
            next_page_position: None,
            last_delivered_position: Some(i64::MAX),
            last_acked_position: Some(i64::MAX),
            state: ReplayState::Live,
            high_water_ref: vec![0x66; 32],
            catch_up_completion: None,
            live_delivery_id: Some(uuid_v7(0x77).to_vec()),
            created_at: "9999-12-31T23:59:59.999999Z".to_owned(),
        };
        let event = ReplayEvent {
            global_position: i64::MAX,
            event_id: uuid_v7(0x88),
            aggregate_type: 1,
            aggregate_id: session.aggregate_id,
            payload: TaskRunEventCodec
                .encode(&gocode_domain::task_run::TaskRunEvent::TaskRunFailed {
                    reason: "x".repeat(gocode_api::MAX_CANONICAL_REPLAY_FAILURE_REASON_BYTES),
                })
                .unwrap(),
            timestamp: i64::MIN,
            event_type: "e".repeat(256),
            sequence: i64::MAX,
            sensitivity: 0,
            schema_version: 1,
            causation_id: Some(uuid_v7(0x99)),
            command_id: uuid_v7(0xaa),
            idempotency_key: "i".repeat(256),
            actor: "a".repeat(256),
            integrity_digest: [0xbb; 32],
            correlation_id: session.aggregate_id,
            correlation_type: 1,
            integrity_profile: 1,
        };
        let authenticated = authenticated_runtime_session(&session);
        let delivery = live_delivery(&authenticated, &service, &session, &event, u64::MAX).unwrap();

        let encoded_reason_bytes = delivery.canonical_event["payload"]["reason"]
            .as_str()
            .unwrap()
            .len();
        let encoded = serde_json::to_vec(&delivery).unwrap();

        assert_eq!(
            encoded_reason_bytes,
            gocode_api::MAX_CANONICAL_REPLAY_FAILURE_REASON_BYTES
        );
        assert!(
            encoded.len() <= MAX_SSE_FRAME_BYTES,
            "actual frame={} declared={MAX_SSE_FRAME_BYTES}",
            encoded.len()
        );
    }
}
