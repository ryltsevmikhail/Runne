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
    provisional_resume_sessions: Arc<Mutex<HashMap<[u8; 16], V2ResumeLeaseState>>>,
    baseline_resume_v2_enabled: bool,
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
            provisional_resume_sessions: Arc::new(Mutex::new(HashMap::new())),
            baseline_resume_v2_enabled: false,
        }
    }
    /// Enables the negotiated V2 baseline-resume transport surface.
    #[must_use]
    pub fn with_baseline_resume_v2(mut self, enabled: bool) -> Self {
        self.baseline_resume_v2_enabled = enabled;
        self
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
        if permits.contains_key(&session_id) {
            return Err(replay_invariant_violation());
        }
        permits.insert(session_id, permit);
        Ok(())
    }

    fn take_session_permit(&self, session_id: &[u8; 16]) -> Option<ReplayCountPermit> {
        self.session_permits
            .lock()
            .ok()
            .and_then(|mut permits| permits.remove(session_id))
    }

    fn release_session_permit(&self, session_id: &[u8; 16]) {
        if let Ok(mut provisional) = self.provisional_resume_sessions.lock() {
            provisional.remove(session_id);
        }
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
