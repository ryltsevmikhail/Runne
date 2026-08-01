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
