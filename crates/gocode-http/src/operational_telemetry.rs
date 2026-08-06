//! Protected operational telemetry transport boundary.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    middleware::Next,
    response::Response,
    routing::get,
};
use gocode_api::{MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1, OperationalTelemetryQueryPort};

const OPERATIONAL_TELEMETRY_PATH: &str = "/v1/runtime/operational-telemetry";

/// Typed query capability required by the operational telemetry route.
#[derive(Clone)]
pub struct OperationalTelemetryHttpState {
    query: Arc<dyn OperationalTelemetryQueryPort>,
}

impl OperationalTelemetryHttpState {
    /// Creates route state from the public telemetry query port.
    #[must_use]
    pub fn new(query: Arc<dyn OperationalTelemetryQueryPort>) -> Self {
        Self { query }
    }
}

/// Builds the operational telemetry endpoint. Authentication is applied by its
/// protected local-runtime host branch.
pub(crate) fn operational_telemetry_router(state: OperationalTelemetryHttpState) -> Router {
    Router::new()
        .route(OPERATIONAL_TELEMETRY_PATH, get(get_operational_telemetry))
        .layer(axum::middleware::from_fn(no_store_response))
        .with_state(state)
}

async fn get_operational_telemetry(
    State(state): State<OperationalTelemetryHttpState>,
    request: Request<Body>,
) -> Response {
    if request.uri().query().is_some() {
        return static_response(StatusCode::BAD_REQUEST);
    }
    let declared_nonzero = match declared_body_size(request.headers()) {
        DeclaredBodySize::TooLarge => return static_response(StatusCode::PAYLOAD_TOO_LARGE),
        DeclaredBodySize::Malformed => {
            return static_response(StatusCode::BAD_REQUEST);
        }
        DeclaredBodySize::Nonzero => true,
        DeclaredBodySize::Absent | DeclaredBodySize::Zero => false,
    };
    let body = match to_bytes(request.into_body(), MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1).await {
        Ok(body) => body,
        Err(_) => return static_response(StatusCode::PAYLOAD_TOO_LARGE),
    };
    if declared_nonzero || !body.is_empty() {
        return static_response(StatusCode::BAD_REQUEST);
    }
    match state.query.query_operational_telemetry() {
        Ok(snapshot) => match serde_json::to_vec(&snapshot) {
            Ok(body) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CACHE_CONTROL, "no-store")
                .body(Body::from(body))
                .unwrap_or_else(|_| static_response(StatusCode::SERVICE_UNAVAILABLE)),
            Err(_) => static_response(StatusCode::SERVICE_UNAVAILABLE),
        },
        Err(_) => static_response(StatusCode::SERVICE_UNAVAILABLE),
    }
}

enum DeclaredBodySize {
    Absent,
    Zero,
    Nonzero,
    TooLarge,
    Malformed,
}

fn declared_body_size(headers: &HeaderMap) -> DeclaredBodySize {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return DeclaredBodySize::Absent;
    };
    if values.next().is_some() {
        return DeclaredBodySize::Malformed;
    }
    let Some(value) = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return DeclaredBodySize::Malformed;
    };
    if value == 0 {
        DeclaredBodySize::Zero
    } else if value > MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1 as u64 {
        DeclaredBodySize::TooLarge
    } else {
        DeclaredBodySize::Nonzero
    }
}

pub(crate) async fn no_store_response(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    if matches!(
        response.status(),
        StatusCode::UNAUTHORIZED
            | StatusCode::BAD_REQUEST
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::METHOD_NOT_ALLOWED
    ) {
        *response.body_mut() = Body::empty();
    }
    response
}

fn static_response(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::empty())
        .expect("static operational telemetry response")
}

#[cfg(test)]
mod tests;
