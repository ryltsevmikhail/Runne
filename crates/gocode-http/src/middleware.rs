//! Shared Axum middleware: request-id injection.
//!
//! The `request_id` middleware ensures every request carries an
//! `x-request-id` header (both incoming and outgoing) for trace
//! correlation across services.

use axum::{extract::Request, http::HeaderName, middleware::Next, response::Response};

static X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Axum middleware that injects `x-request-id` into the request
/// and response headers using a v7 UUID.
pub async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = uuid::Uuid::now_v7().to_string();
    request
        .headers_mut()
        .insert(X_REQUEST_ID.clone(), request_id.parse().unwrap());

    let mut response = next.run(request).await;

    response.headers_mut().insert(
        X_REQUEST_ID.clone(),
        uuid::Uuid::now_v7().to_string().parse().unwrap(),
    );

    response
}
