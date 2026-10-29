use super::*;
use axum::{extract::State, http::HeaderMap, response::IntoResponse};

pub(super) async fn close(
    State(state): State<LocalSessionHttpState>,
    headers: HeaderMap,
) -> Response {
    let (Some(authority), Some(now)) = (
        crate::auth::extract_session_authority(&headers),
        (state.clock)(),
    ) else {
        return rejected();
    };
    let Ok(mut service) = state.service.lock() else {
        return rejected();
    };
    match service.close_session(&authority, now.session_monotonic) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => rejected(),
    }
}
