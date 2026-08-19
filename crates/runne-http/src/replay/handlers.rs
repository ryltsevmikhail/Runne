async fn open_session(
    State(state): State<ReplayHttpState>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(authenticated): Extension<AuthenticatedRuntimeSession>,
    Extension(baseline_context): Extension<
        runne_application::local_session::AuthenticatedReplayResumeContextV2,
    >,
    Extension(request_id): Extension<RequestId>,
    body: Result<Json<OpenSessionRequest>, JsonRejection>,
) -> Response {
    let result: Result<Response, ReplayHttpFailure> = async {
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
        if authenticated.binding.stable().principal_id() != principal.as_api_principal() {
            return Err(replay_authorization_revoked());
        }
        let session_permit = state
            .quotas
            .reserve_session(principal.as_api_principal().as_str())
            .map_err(|_| replay_backpressure())?;
        let from_cursor = req.from_cursor.as_deref().map(decode_cursor).transpose()?;
        let delivery_guard = Arc::new(OpenSessionDeliveryGuard {
            authenticated: authenticated.clone(),
            service: Arc::clone(&state.service),
            prohibited_content: Arc::clone(&state.prohibited_content),
        });
        let opened = state
            .service
            .open_session_with_baseline_context(
                principal.as_api_principal().as_str(),
                state.binding.session_generation,
                &state.binding.authority_id,
                state.binding.authorization_epoch,
                aggregate_type,
                &aggregate_id,
                from_cursor,
                delivery_guard,
                Some(&baseline_context),
                state.baseline_resume_v2_enabled,
            )
            .await;
        let (session, events) = match opened {
            Ok(opened) => opened,
            Err(ReplayError::ReplayRetentionGap { baseline }) => {
                return retention_baseline_response(
                    &baseline,
                    &request_id,
                    state.prohibited_content.as_ref(),
                );
            }
            Err(ReplayError::ReplayRetentionGapV2 { baseline }) => {
                return retention_baseline_v2_response(
                    &baseline,
                    &request_id,
                    state.prohibited_content.as_ref(),
                );
            }
            Err(error) => return Err(replay_error_to_http(&error)),
        };
        let response =
            open_session_response(&authenticated, state.service.as_ref(), &session, &events)?;
        state.retain_session_permit(session.session_id, session_permit)?;
        bounded_json_response(StatusCode::OK, &response)
    }
    .await;
    match result {
        Ok(response) => response,
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
