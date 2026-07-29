//! Shared Axum middleware: request-id injection.
//!
//! The `request_id` middleware ensures every request carries an
//! `x-request-id` header (both incoming and outgoing) for trace
//! correlation across services.

use axum::{
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};

use crate::error::RequestId;

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Axum middleware that injects `x-request-id` into the request
/// and response headers using a v7 UUID.
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = RequestId::generate();
    request.extensions_mut().insert(request_id.clone());
    request.headers_mut().insert(
        X_REQUEST_ID.clone(),
        HeaderValue::from_str(request_id.as_str())
            .expect("generated UUIDv7 request identity is a valid header value"),
    );

    let mut response = next.run(request).await;

    response.headers_mut().insert(
        X_REQUEST_ID.clone(),
        HeaderValue::from_str(request_id.as_str())
            .expect("generated UUIDv7 request identity is a valid header value"),
    );

    response
}
