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
    let digest = Sha256::digest([b"runne/live-delivery-id/v1\0".as_slice(), value].concat());
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
