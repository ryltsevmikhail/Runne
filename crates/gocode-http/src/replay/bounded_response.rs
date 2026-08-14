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
