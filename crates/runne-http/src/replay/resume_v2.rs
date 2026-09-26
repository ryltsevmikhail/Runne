use base64::Engine as _;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResumeFromBaselineResponse {
    request_id: String,
    session_id: String,
    high_water_ref: String,
    baseline_checkpoint: String,
    accepted_promotion: AcceptedPromotionWire,
    events: Vec<DeliveredReplayEventWire>,
    has_more: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedPromotionWire {
    codec: u8,
    projection_bytes: String,
    projection_digest: String,
    sequence: u64,
    version: u64,
    global_position: i64,
    head_event_id: String,
    head_integrity_digest: String,
    captured_high_water: i64,
}

async fn resume_from_baseline(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(authenticated): Extension<AuthenticatedRuntimeSession>,
    Extension(context): Extension<
        runne_application::local_session::AuthenticatedReplayResumeContextV2,
    >,
    Extension(request_id): Extension<RequestId>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let result: Result<Response, ReplayHttpFailure> = async {
        if !exact_json_content_type(&headers) {
            return Err(ReplayHttpFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ));
        }
        let request = strict_resume_request(&body)?;
        let (scope, wire) = parse_resume_baseline(request.baseline)?;
        inspect_replay_bytes(
            state.prohibited_content.as_ref(),
            &wire.to_unauthenticated_fields().promotion_projection_bytes,
        )
        .map_err(|error| replay_error_to_http(&error))?;
        if authenticated.binding.stable().principal_id() != principal.as_api_principal() {
            return Err(replay_authorization_revoked());
        }
        let binding = state.binding_for_authenticated(&authenticated)?;
        let permit = state
            .quotas
            .reserve_session(principal.as_api_principal().as_str())
            .map_err(|_| replay_backpressure())?;
        let delivery_guard = Arc::new(OpenSessionDeliveryGuard {
            authenticated: authenticated.clone(),
            service: Arc::clone(&state.service),
            prohibited_content: Arc::clone(&state.prohibited_content),
        });
        let (session, events, baseline_cursor, accepted) = owned_resume_admission(
            &state,
            OwnedResumeAdmission {
                principal_id: principal.as_api_principal().as_str().to_owned(),
                scope,
                wire,
                context,
                delivery_guard,
                permit,
                binding,
            },
        )
        .await
        .map_err(|error| replay_error_to_http(&error))?;
        let mut admission = ResumeAdmissionGuard::new(
            state.clone(),
            principal.as_api_principal().as_str().to_owned(),
            session.session_id,
        );
        let open =
            open_session_response(&authenticated, state.service.as_ref(), &session, &events)?;
        let response = ResumeFromBaselineResponse {
            request_id: request_id.as_str().to_owned(),
            baseline_checkpoint: encode_cursor(&baseline_cursor)?,
            accepted_promotion: AcceptedPromotionWire {
                codec: accepted.codec(),
                projection_bytes: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(accepted.bytes()),
                projection_digest: hex::encode(accepted.digest()),
                sequence: accepted.sequence(),
                version: accepted.version(),
                global_position: accepted.global_position(),
                head_event_id: hex::encode(accepted.head_event_id()),
                head_integrity_digest: hex::encode(accepted.head_integrity_digest()),
                captured_high_water: accepted.captured_high_water(),
            },
            session_id: open.session_id,
            high_water_ref: open.high_water_ref,
            events: open.events,
            has_more: open.has_more,
        };
        let response_bytes =
            serde_json::to_vec(&response).map_err(|_| replay_invariant_violation())?;
        inspect_replay_bytes(state.prohibited_content.as_ref(), &response_bytes)
            .map_err(|error| replay_error_to_http(&error))?;
        let mut response = bounded_json_response(StatusCode::OK, &response)?;
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        response.headers_mut().insert(
            axum::http::HeaderName::from_static("x-request-id"),
            axum::http::HeaderValue::from_str(request_id.as_str())
                .map_err(|_| replay_invariant_violation())?,
        );
        admission.response_delivered()?;
        Ok(response)
    }
    .await;
    result.unwrap_or_else(|error| error.into_response(&request_id))
}

/// Transfers every failed response path into the retry-backed provisional reaper.
struct ResumeAdmissionGuard {
    state: ReplayHttpState,
    principal_id: String,
    session_id: Option<[u8; 16]>,
}

impl ResumeAdmissionGuard {
    fn new(state: ReplayHttpState, principal_id: String, session_id: [u8; 16]) -> Self {
        Self {
            state,
            principal_id,
            session_id: Some(session_id),
        }
    }

    fn response_delivered(&mut self) -> Result<(), ReplayHttpFailure> {
        self.session_id
            .take()
            .map(|_| ())
            .ok_or_else(replay_invariant_violation)
    }
}

impl Drop for ResumeAdmissionGuard {
    fn drop(&mut self) {
        let Some(session_id) = self.session_id.take() else {
            return;
        };
        self.state
            .begin_v2_resume_reaping(session_id, self.principal_id.clone());
    }
}

fn exact_json_content_type(headers: &axum::http::HeaderMap) -> bool {
    let values: Vec<_> = headers
        .get_all(axum::http::header::CONTENT_TYPE)
        .iter()
        .collect();
    values.len() == 1 && values[0].to_str().ok() == Some("application/json")
}

fn parse_resume_baseline(
    value: ResumeBaselineWireV2,
) -> Result<(ReplayScope, runne_api::ReplayRetentionBaselineWireV2), ReplayHttpFailure> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let fixed = |value: String, length| {
        let bytes = hex::decode(&value).ok()?;
        (value.len() == length * 2
            && bytes.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
        .then_some(bytes)
    };
    let id: [u8; 16] = fixed(value.aggregate_id.clone(), 16)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let kind = match value.aggregate_kind.as_str() {
        "taskRun" => runne_api::ApiReplayAggregateKind::TaskRun,
        "conversation" => runne_api::ApiReplayAggregateKind::Conversation,
        _ => {
            return Err(ReplayHttpFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ));
        }
    };
    let to16 = |value: String| {
        fixed(value, 16)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request"))
    };
    let to32 = |value: String| {
        fixed(value, 32)
            .and_then(|value| value.try_into().ok())
            .ok_or_else(|| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request"))
    };
    let wire = runne_api::ReplayRetentionBaselineWireV2::from_unauthenticated_fields(
        runne_api::UnauthenticatedReplayRetentionBaselineFieldsV2 {
            schema_version: value.schema_version,
            authority_id: to16(value.authority_id)?,
            principal_id: value.principal_id,
            lineage_id: to16(value.lineage_id)?,
            runtime_session_binding_digest: to32(value.runtime_session_binding_digest)?,
            replay_scope_digest: to32(value.replay_scope_digest)?,
            aggregate_kind: kind,
            aggregate_id: id,
            sequence: value.sequence,
            version: value.version,
            baseline_global_position: value.baseline_global_position,
            head_event_id: to16(value.head_event_id)?,
            head_integrity_digest: to32(value.head_integrity_digest)?,
            promotion_codec: value.promotion_codec,
            promotion_projection_bytes: URL_SAFE_NO_PAD
                .decode(value.promotion_projection_bytes)
                .map_err(|_| ReplayHttpFailure::new(StatusCode::BAD_REQUEST, "invalid_request"))?,
            promotion_projection_digest: to32(value.promotion_projection_digest)?,
            retained_floor: value.retained_floor,
            captured_high_water: value.captured_high_water,
            retention_generation: value.retention_generation,
            retention_manifest_digest: to32(value.retention_manifest_digest)?,
            issued_at_unix_ms: value.issued_at_unix_ms,
            expires_at_unix_ms: value.expires_at_unix_ms,
            witness_mac: to32(value.witness_mac)?,
        },
    );
    Ok((
        ReplayScope::Aggregate {
            aggregate_type: match kind {
                runne_api::ApiReplayAggregateKind::TaskRun => 1,
                runne_api::ApiReplayAggregateKind::Conversation => 2,
            },
            aggregate_id: id,
        },
        wire,
    ))
}
