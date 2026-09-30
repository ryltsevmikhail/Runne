//! Conversation writer-lease take-control surface (X2 writer lease v1).
//!
//! One authenticated POST rotates the durable conversation writer lease to
//! the requesting principal after the exact expected fencing token matches.
//! The lease never expires on its own; take-control is the only ownership
//! change (plan 18 §D1.3/X2: lease expiry does not prove the old writer
//! died).

use std::sync::{Arc, Mutex};

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;

use crate::auth::AuthenticatedPrincipal;
use crate::error::{RequestId, canonical_error_response};

/// Store-backed take-control boundary: serializes lease rotations behind the
/// same writer connection the conversation commits use.
pub trait ConversationWriterLeaseHostPort: Send + Sync {
    /// Rotates the lease; returns the new fencing token.
    fn take_control(
        &self,
        principal: &str,
        conversation_id: [u8; 16],
        expected_token: u64,
    ) -> Result<u64, WriterLeaseHostError>;
}

/// Closed take-control failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterLeaseHostError {
    /// The expected fencing token did not match the durable lease.
    Conflict,
    /// The durable store is unavailable.
    Unavailable,
}

/// Shared state for the writer-lease routes.
pub struct ConversationWriterLeaseHttpState<H> {
    host: Arc<H>,
}

impl<H> Clone for ConversationWriterLeaseHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
        }
    }
}

impl<H> ConversationWriterLeaseHttpState<H> {
    /// Wraps the lease host for the router.
    pub fn new(host: Arc<H>) -> Self {
        Self { host }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TakeControlBody {
    expected_fencing_token: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TakeControlResponse {
    fencing_token: u64,
}

/// Builds the writer-lease route set.
pub fn conversation_writer_lease_router<H>(
    state: ConversationWriterLeaseHttpState<H>,
) -> axum::Router
where
    H: ConversationWriterLeaseHostPort + 'static,
{
    axum::Router::new()
        .route(
            "/v1/conversations/{conversation_id}/writer-lease/take-control",
            post(take_control::<H>),
        )
        .with_state(state)
}

async fn take_control<H>(
    State(state): State<ConversationWriterLeaseHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(conversation_id): Path<String>,
    body: Result<Json<TakeControlBody>, axum::extract::rejection::JsonRejection>,
) -> Response
where
    H: ConversationWriterLeaseHostPort,
{
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => {
            return canonical_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &request_id,
            );
        }
    };
    let bytes: [u8; 16] = match conversation_id
        .parse::<uuid::Uuid>()
        .ok()
        .and_then(|value| value.as_bytes().as_slice().try_into().ok())
    {
        Some(bytes) => bytes,
        None => {
            return canonical_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_conversation_id",
                &request_id,
            );
        }
    };
    match state.host.take_control(
        principal.as_api_principal().as_str(),
        bytes,
        body.expected_fencing_token,
    ) {
        Ok(token) => Json(TakeControlResponse {
            fencing_token: token,
        })
        .into_response(),
        Err(WriterLeaseHostError::Conflict) => canonical_error_response(
            StatusCode::CONFLICT,
            "conversation_writer_lease_conflict",
            &request_id,
        ),
        Err(WriterLeaseHostError::Unavailable) => canonical_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
            &request_id,
        ),
    }
}

/// Adapts the durable store transaction into the HTTP lease host port.
pub struct StoreConversationWriterLeaseHost {
    store: std::sync::Mutex<runne_store::store::StoreTransaction>,
}

impl StoreConversationWriterLeaseHost {
    /// Wraps the shared store transaction.
    pub fn new(store: runne_store::store::StoreTransaction) -> Self {
        Self {
            store: Mutex::new(store),
        }
    }
}

impl ConversationWriterLeaseHostPort for StoreConversationWriterLeaseHost {
    fn take_control(
        &self,
        principal: &str,
        conversation_id: [u8; 16],
        expected_token: u64,
    ) -> Result<u64, WriterLeaseHostError> {
        let store = self
            .store
            .lock()
            .map_err(|_| WriterLeaseHostError::Unavailable)?;
        store
            .take_control_conversation_writer_lease(&conversation_id, principal, expected_token)
            .map_err(|error| match error {
                runne_store::conversation_writer_lease::WriterLeaseError::Conflict => {
                    WriterLeaseHostError::Conflict
                }
                _ => WriterLeaseHostError::Unavailable,
            })
    }
}
