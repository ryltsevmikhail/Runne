//! Replay HTTP handlers — canonical replay session API.
//!
//! Six POST endpoints implement the ADR-0013 replay session lifecycle:
//! open-session, read-page, acknowledge, complete-catch-up, continue-live, close.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use gocode_application::replay_service::{
    ReplayDeliveryPrecommitGuard, ReplayError, ReplayEvent, ReplayService, ReplaySession,
};
use gocode_domain::replay::{ReplayCursor, ReplayScope};
use serde::{Deserialize, Serialize};

use crate::auth::AuthenticatedPrincipal;
use crate::error::{RequestId, canonical_error_response};
use crate::limits::LimitsConfig;
use crate::sse::{SseDelivery, SseItem, SseTerminalFrame, into_sse_stream, sse_channel};

const MAX_REPLAY_BODY_BYTES: usize = 8 * 1024;
const MAX_CURSOR_TOKEN_BYTES: usize = 8 * 1024;
const CURSOR_TOKEN_PREFIX: &str = "gocode-replay-cursor-v1.";
const LIVE_CHANNEL_CAPACITY: usize = 64;
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
        }
    }

    fn claim_page_read(&self, session_id: [u8; 16]) -> Option<SessionClaim> {
        SessionClaim::acquire(Arc::clone(&self.active_page_reads), session_id)
    }

    fn claim_live_drain(&self, session_id: [u8; 16]) -> bool {
        self.active_drains
            .lock()
            .map(|mut drains| drains.insert(session_id))
            .unwrap_or(false)
    }

    fn release_live_drain(&self, session_id: &[u8; 16]) {
        if let Ok(mut drains) = self.active_drains.lock() {
            drains.remove(session_id);
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
    pub aggregate_type: i32,
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

/// Sanitized HTTP DTO for a replay event.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredReplayEventWire {
    pub global_position: i64,
    pub event_id: String,
    pub aggregate_type: i32,
    pub aggregate_id: String,
    pub sequence: i64,
    pub timestamp: i64,
    pub sensitivity: &'static str,
    pub schema_version: u32,
    pub event_type: String,
    pub causation_id: Option<String>,
    pub command_id: String,
    pub idempotency_key: String,
    pub actor: String,
    pub integrity_digest: String,
    pub correlation_id: String,
    pub correlation_type: i32,
    pub integrity_profile: i32,
    pub payload: ReplayPayloadWire,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveredReplayEventWire {
    #[serde(flatten)]
    pub event: StoredReplayEventWire,
    pub cursor: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayPayloadWire {
    pub encoding: &'static str,
    pub data: String,
}

fn event_id_hex(bytes: &[u8; 16]) -> String {
    hex::encode(bytes)
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

fn wire_event(event: &ReplayEvent) -> Result<StoredReplayEventWire, ReplayHttpFailure> {
    let sensitivity = match event.sensitivity {
        0 => "public",
        1 => "internal",
        2 => "sensitive",
        _ => return Err(replay_invariant_violation()),
    };
    if event.schema_version == 0
        || !matches!(event.aggregate_type, 1 | 2)
        || !matches!(event.correlation_type, 1 | 2)
        || !matches!(event.integrity_profile, 1 | 2)
    {
        return Err(replay_invariant_violation());
    }
    Ok(StoredReplayEventWire {
        global_position: event.global_position,
        event_id: event_id_hex(&event.event_id),
        aggregate_type: event.aggregate_type,
        aggregate_id: event_id_hex(&event.aggregate_id),
        sequence: event.sequence,
        timestamp: event.timestamp,
        sensitivity,
        schema_version: event.schema_version,
        event_type: event.event_type.clone(),
        causation_id: event.causation_id.as_ref().map(event_id_hex),
        command_id: event_id_hex(&event.command_id),
        idempotency_key: event.idempotency_key.clone(),
        actor: event.actor.clone(),
        integrity_digest: hex::encode(event.integrity_digest),
        correlation_id: event_id_hex(&event.correlation_id),
        correlation_type: event.correlation_type,
        integrity_profile: event.integrity_profile,
        payload: ReplayPayloadWire {
            encoding: "gocode-durable-event-codec-v1-hex",
            data: hex::encode(&event.payload),
        },
    })
}

fn wire_delivery(
    event: &ReplayEvent,
    cursor: &ReplayCursor,
) -> Result<DeliveredReplayEventWire, ReplayHttpFailure> {
    Ok(DeliveredReplayEventWire {
        event: wire_event(event)?,
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
            wire_delivery(event, &cursor)
        })
        .collect()
}

fn open_session_response(
    service: &ReplayService,
    session: &ReplaySession,
    events: &[ReplayEvent],
) -> Result<OpenSessionResponse, ReplayHttpFailure> {
    Ok(OpenSessionResponse {
        session_id: session_id_hex(&session.session_id),
        high_water_ref: high_water_ref_hex(&session.high_water_ref),
        events: wire_deliveries(service, session, events)?,
        has_more: session.next_page_position.is_some(),
    })
}

fn read_page_response(
    service: &ReplayService,
    session: &ReplaySession,
    events: &[ReplayEvent],
) -> Result<ReadPageResponse, ReplayHttpFailure> {
    Ok(ReadPageResponse {
        events: wire_deliveries(service, session, events)?,
        has_more: session.next_page_position.is_some(),
    })
}

struct OpenSessionDeliveryGuard {
    service: Arc<ReplayService>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

impl ReplayDeliveryPrecommitGuard for OpenSessionDeliveryGuard {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError> {
        let response = open_session_response(self.service.as_ref(), session, events)
            .map_err(|_| replay_delivery_integrity_error())?;
        let bytes = serde_json::to_vec(&response).map_err(|_| replay_delivery_integrity_error())?;
        inspect_replay_bytes(self.prohibited_content.as_ref(), &bytes)
    }
}

struct ReadPageDeliveryGuard {
    service: Arc<ReplayService>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

impl ReplayDeliveryPrecommitGuard for ReadPageDeliveryGuard {
    fn inspect(&self, session: &ReplaySession, events: &[ReplayEvent]) -> Result<(), ReplayError> {
        let response = read_page_response(self.service.as_ref(), session, events)
            .map_err(|_| replay_delivery_integrity_error())?;
        let bytes = serde_json::to_vec(&response).map_err(|_| replay_delivery_integrity_error())?;
        inspect_replay_bytes(self.prohibited_content.as_ref(), &bytes)
    }
}

fn session_id_hex(id: &[u8; 16]) -> String {
    hex::encode(id)
}

fn high_water_ref_hex(high_water_ref: &[u8]) -> String {
    hex::encode(high_water_ref)
}

fn parse_aggregate_id(hex_id: &str) -> Result<[u8; 16], ReplayHttpFailure> {
    let bytes = hex::decode(hex_id)
        .map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_aggregate_id"))?;
    bytes
        .try_into()
        .map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_aggregate_id"))
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

fn replay_error_to_http(error: &ReplayError) -> ReplayHttpFailure {
    match error {
        ReplayError::SessionNotFound => {
            ReplayHttpFailure::new(StatusCode::NOT_FOUND, "replay_session_not_found")
        }
        ReplayError::Unauthorized(_) | ReplayError::AuthorizationRevoked => {
            ReplayHttpFailure::new(StatusCode::UNAUTHORIZED, "unauthorized")
        }
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
        ReplayError::Integrity(_) => replay_invariant_violation(),
        ReplayError::CursorInvalid { .. } => invalid_replay_cursor(),
        ReplayError::SensitivityDenied => {
            ReplayHttpFailure::new(StatusCode::FORBIDDEN, "replay_sensitivity_denied")
        }
        ReplayError::BackpressureExceeded => {
            ReplayHttpFailure::new(StatusCode::TOO_MANY_REQUESTS, "replay_backpressure")
        }
    }
}

async fn open_session(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    body: Result<Json<OpenSessionRequest>, JsonRejection>,
) -> Response {
    let result: Result<OpenSessionResponse, ReplayHttpFailure> = async {
        let Json(req) =
            body.map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request"))?;
        let aggregate_id = parse_aggregate_id(&req.aggregate_id)?;
        let aggregate_type = u8::try_from(req.aggregate_type).map_err(|_| {
            ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "unsupported_replay_scope")
        })?;
        if !matches!(aggregate_type, 1 | 2) {
            return Err(ReplayHttpFailure::new(
                StatusCode::BAD_REQUEST,
                "unsupported_replay_scope",
            ));
        }
        let from_cursor = req.from_cursor.as_deref().map(decode_cursor).transpose()?;
        let delivery_guard = Arc::new(OpenSessionDeliveryGuard {
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
                req.aggregate_type,
                &aggregate_id,
                from_cursor,
                delivery_guard,
            )
            .await
            .map_err(|error| replay_error_to_http(&error))?;

        open_session_response(state.service.as_ref(), &session, &events)
    }
    .await;

    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => error.into_response(&request_id),
    }
}

async fn read_page(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(session_hex): Path<String>,
    body: Result<Json<ReadPageRequest>, JsonRejection>,
) -> Response {
    let result: Result<ReadPageResponse, ReplayHttpFailure> = async {
        let Json(req) =
            body.map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request"))?;
        let session_id = extract_session_id(&session_hex)?;
        let limit = req.limit.unwrap_or(state.limits.default_page_size);
        if limit == 0 || limit > state.limits.max_page_size {
            return Err(ReplayHttpFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_replay_page_limit",
            ));
        }
        let _page_claim = state.claim_page_read(session_id).ok_or_else(|| {
            ReplayHttpFailure::new(StatusCode::CONFLICT, "replay_page_in_progress")
        })?;
        let delivery_guard = Arc::new(ReadPageDeliveryGuard {
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
            .map_err(|error| replay_error_to_http(&error))?;

        read_page_response(state.service.as_ref(), &session, &events)
    }
    .await;

    match result {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => error.into_response(&request_id),
    }
}

async fn acknowledge(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(session_hex): Path<String>,
    body: Result<Json<AcknowledgeRequest>, JsonRejection>,
) -> Response {
    let result: Result<AcknowledgeResponse, ReplayHttpFailure> = async {
        let Json(req) =
            body.map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request"))?;
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
            .map_err(|error| replay_error_to_http(&error))?;
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
            .map_err(|error| replay_error_to_http(&error))?;
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
            .map_err(|error| replay_error_to_http(&error))?;
        let live_delivery_id = session
            .live_delivery_id
            .filter(|id| id.len() == 16)
            .map(hex::encode)
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
            .map_err(|error| replay_error_to_http(&error))
    }
    .await;

    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response(&request_id),
    }
}

fn terminal(reason: &'static str, message: &'static str) -> SseItem {
    SseItem::Terminal(SseTerminalFrame {
        transport_version: 1,
        reason: reason.to_owned(),
        message: message.to_owned(),
    })
}

fn try_terminal(sender: &tokio::sync::mpsc::Sender<SseItem>, item: SseItem) {
    let _ = sender.try_send(item);
}

fn live_delivery(
    service: &ReplayService,
    session: &ReplaySession,
    event: &ReplayEvent,
    delivery_sequence: u64,
) -> Result<SseDelivery, ReplayHttpFailure> {
    if event.aggregate_type != session.aggregate_type
        || event.aggregate_id != session.aggregate_id
        || !matches!(event.sensitivity, 0..=2)
        || event.schema_version == 0
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
    let canonical_event = wire_event(event)
        .ok()
        .and_then(|event| serde_json::to_value(event).ok())
        .ok_or_else(replay_invariant_violation)?;
    let live_delivery_id = session
        .live_delivery_id
        .as_deref()
        .filter(|id| id.len() == 16)
        .map(hex::encode)
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
            let delivery = live_delivery(self.service.as_ref(), session, event, delivery_sequence)
                .map_err(|_| replay_delivery_integrity_error())?;
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
    first_delivery_sequence: u64,
) -> Arc<dyn ReplayDeliveryPrecommitGuard> {
    Arc::new(LiveDeliveryGuard {
        service: Arc::clone(&state.service),
        prohibited_content: Arc::clone(&state.prohibited_content),
        first_delivery_sequence,
    })
}

async fn produce_live_events(
    state: ReplayHttpState,
    session_id: [u8; 16],
    principal_id: String,
    mut session: gocode_application::replay_service::ReplaySession,
    mut events: Vec<ReplayEvent>,
    sender: tokio::sync::mpsc::Sender<SseItem>,
) {
    let mut delivery_sequence = 1_u64;
    let mut stop = false;
    let mut preserve_session = false;

    while !stop && !sender.is_closed() {
        for event in events.drain(..) {
            let delivery =
                match live_delivery(state.service.as_ref(), &session, &event, delivery_sequence) {
                    Ok(delivery) => delivery,
                    Err(_) => {
                        try_terminal(
                            &sender,
                            terminal("UnsupportedSchema", "stored replay event is invalid"),
                        );
                        stop = true;
                        break;
                    }
                };
            let delivery_bytes = match serde_json::to_vec(&delivery) {
                Ok(bytes) => bytes,
                Err(_) => {
                    try_terminal(
                        &sender,
                        terminal("UnsupportedSchema", "replay event encoding failed"),
                    );
                    stop = true;
                    break;
                }
            };
            let frame_size = delivery_bytes.len();
            if frame_size > MAX_SSE_FRAME_BYTES {
                try_terminal(
                    &sender,
                    terminal("BackpressureExceeded", "replay frame exceeds stream limit"),
                );
                stop = true;
                break;
            }
            match sender.try_send(SseItem::Delivery(delivery)) {
                Ok(()) => {
                    delivery_sequence = match delivery_sequence.checked_add(1) {
                        Some(next) => next,
                        None => {
                            try_terminal(
                                &sender,
                                terminal("BackpressureExceeded", "delivery sequence limit reached"),
                            );
                            stop = true;
                            break;
                        }
                    };
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    try_terminal(
                        &sender,
                        terminal("BackpressureExceeded", "slow replay consumer"),
                    );
                    stop = true;
                    break;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
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
                live_delivery_guard(&state, delivery_sequence),
            )
            .await
        {
            Ok((next_session, next_events)) => {
                session = next_session;
                events = next_events;
            }
            Err(
                ReplayError::Unauthorized(_)
                | ReplayError::AuthorizationRevoked
                | ReplayError::StaleGeneration,
            ) => {
                try_terminal(
                    &sender,
                    terminal("Unauthorized", "replay authorization expired"),
                );
                break;
            }
            Err(ReplayError::SensitivityDenied) => {
                try_terminal(
                    &sender,
                    terminal("SensitivityDenied", "event sensitivity is not permitted"),
                );
                preserve_session = true;
                break;
            }
            Err(ReplayError::ReplayRetentionGap { .. }) => {
                try_terminal(
                    &sender,
                    terminal("RetentionGap", "replay history is unavailable"),
                );
                break;
            }
            Err(_) => {
                try_terminal(
                    &sender,
                    terminal("SessionClosed", "replay stream terminated"),
                );
                break;
            }
        }
    }

    if !preserve_session {
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
    state.release_live_drain(&session_id);
}

async fn stream_live(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(session_hex): Path<String>,
) -> Response {
    let session_id = match extract_session_id(&session_hex) {
        Ok(session_id) => session_id,
        Err(error) => return error.into_response(&request_id),
    };
    if !state.claim_live_drain(session_id) {
        return ReplayHttpFailure::new(StatusCode::CONFLICT, "replay_session_conflict")
            .into_response(&request_id);
    }
    let principal_id = principal.as_api_principal().as_str().to_owned();
    let initial = state
        .service
        .poll_live(
            &session_id,
            &principal_id,
            state.binding.session_generation,
            &state.binding.authority_id,
            state.binding.authorization_epoch,
            live_delivery_guard(&state, 1),
        )
        .await;
    let (session, events) = match initial {
        Ok(initial) => initial,
        Err(error) => {
            state.release_live_drain(&session_id);
            return replay_error_to_http(&error).into_response(&request_id);
        }
    };
    let (sender, receiver) = sse_channel(LIVE_CHANNEL_CAPACITY);
    tokio::spawn(produce_live_events(
        state,
        session_id,
        principal_id,
        session,
        events,
        sender,
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
    use gocode_application::replay_service::{
        REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES, REPLAY_EVENT_VARIABLE_MAX_BYTES,
        REPLAY_FRAME_CAPACITY_BYTES,
    };

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
    fn maximum_payload_bearing_http_frame_fits_declared_capacity() {
        let cursor = format!(
            "{CURSOR_TOKEN_PREFIX}{}",
            "ab".repeat(MAX_CURSOR_TOKEN_BYTES)
        );
        let payload_data = "ab".repeat(REPLAY_EVENT_VARIABLE_MAX_BYTES / 2);
        let event = DeliveredReplayEventWire {
            event: StoredReplayEventWire {
                global_position: i64::MAX,
                event_id: "a".repeat(32),
                aggregate_type: 2,
                aggregate_id: "b".repeat(32),
                sequence: i64::MAX,
                timestamp: i64::MIN,
                sensitivity: "sensitive",
                schema_version: u32::MAX,
                event_type: "e".repeat(256),
                causation_id: Some("c".repeat(32)),
                command_id: "d".repeat(32),
                idempotency_key: "i".repeat(256),
                actor: "a".repeat(256),
                integrity_digest: "f".repeat(64),
                correlation_id: "1".repeat(32),
                correlation_type: 2,
                integrity_profile: 2,
                payload: ReplayPayloadWire {
                    encoding: "gocode-durable-event-codec-v1-hex",
                    data: payload_data,
                },
            },
            cursor,
        };
        let response = OpenSessionResponse {
            session_id: "2".repeat(32),
            high_water_ref: "3".repeat(64),
            events: vec![event],
            has_more: true,
        };

        let encoded = serde_json::to_vec(&response).unwrap();
        let actual_wrapper_bytes = encoded.len() - REPLAY_EVENT_VARIABLE_MAX_BYTES;

        assert!(
            actual_wrapper_bytes <= REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES,
            "actual wrapper={actual_wrapper_bytes} \
             declared={REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES}"
        );
        assert!(
            encoded.len() <= REPLAY_FRAME_CAPACITY_BYTES,
            "actual frame={} declared={REPLAY_FRAME_CAPACITY_BYTES}",
            encoded.len()
        );
    }
}
