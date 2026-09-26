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
    let binding = match state.binding_for_authenticated(&authenticated) {
        Ok(binding) => binding,
        Err(error) => return error.into_response(&request_id),
    };
    let live_permit = match state.quotas.reserve_live(&principal_id) {
        Ok(permit) => permit,
        Err(_) => return replay_backpressure().into_response(&request_id),
    };
    let initial = state
        .service
        .poll_live(
            &session_id,
            &principal_id,
            binding.session_generation,
            &binding.authority_id,
            binding.authorization_epoch,
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
    let delivery_claim = state.claim_v2_resume_delivery(&session_id);
    if delivery_claim == V2ResumeDeliveryClaim::Reaping {
        return ReplayHttpFailure::new(StatusCode::GONE, "replay_session_expired")
            .into_response(&request_id);
    }
    let session_permit = match state.take_session_permit(&session_id) {
        Some(permit) => permit,
        None => {
            if delivery_claim == V2ResumeDeliveryClaim::Delivered {
                state.fail_v2_resume_delivery(session_id, principal_id);
            }
            return replay_backpressure().into_response(&request_id);
        }
    };
    if delivery_claim == V2ResumeDeliveryClaim::Delivered {
        state.finish_v2_resume_delivery(&session_id);
    }
    let (sender, receiver) = sse_channel_with_quota(MAX_LIVE_QUEUE_FRAMES, state.quotas.queue());
    tokio::spawn(produce_live_events(
        LiveProducer {
            state,
            session_id,
            principal_id,
            authenticated,
            binding,
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
