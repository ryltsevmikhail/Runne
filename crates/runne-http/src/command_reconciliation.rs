//! Authenticated read-only command reconciliation HTTP adapter.

use std::sync::Arc;

use axum::{
    Router,
    extract::{DefaultBodyLimit, Request},
    http::header,
    middleware::{self, Next},
    response::Response,
    routing::post,
};
use runne_api::CommandReconciliationHostPort;

use crate::error::{RequestId, canonical_error_response};

mod handlers;
mod response;
mod wire;

const MAX_RECONCILIATION_BODY_BYTES: usize = runne_api::max_message_text_bytes() + 4 * 1024;

/// Shared HTTP state containing only the read-only reconciliation host.
pub struct CommandReconciliationHttpState<H> {
    pub(super) host: Arc<H>,
}
impl<H> Clone for CommandReconciliationHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
        }
    }
}
impl<H> CommandReconciliationHttpState<H> {
    /// Wraps the closed reconciliation host port.
    #[must_use]
    pub fn new(host: H) -> Self {
        Self {
            host: Arc::new(host),
        }
    }
}
/// Builds the isolated route before the production authentication contour.
pub fn command_reconciliation_router<H>(state: CommandReconciliationHttpState<H>) -> Router
where
    H: CommandReconciliationHostPort + 'static,
{
    Router::new()
        .route("/v1/commands/reconcile", post(handlers::reconcile::<H>))
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(MAX_RECONCILIATION_BODY_BYTES))
        .layer(middleware::from_fn(declared_body_limit))
        .with_state(state)
}
async fn method_not_allowed(request: axum::extract::Request) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(RequestId::generate);
    canonical_error_response(
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        &request_id,
    )
}
async fn declared_body_limit(request: axum::extract::Request, next: middleware::Next) -> Response {
    let exceeds = request
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|value| value > MAX_RECONCILIATION_BODY_BYTES);
    if exceeds {
        let request_id = request
            .extensions()
            .get::<RequestId>()
            .cloned()
            .unwrap_or_else(RequestId::generate);
        return canonical_error_response(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            &request_id,
        );
    }
    next.run(request).await
}

pub(crate) async fn no_store_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
}
