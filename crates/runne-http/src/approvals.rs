//! Authenticated HTTP projection of runtime-owned approvals.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use runne_api::{ApiActor, ApprovalCommandHostPort, ApprovalQueryHostPort};
use std::sync::Arc;

const MAX_BODY_BYTES: usize = 16 * 1024;

/// Shared approval host state and the runtime actor identity.
pub struct ApprovalHttpState<H> {
    pub(super) host: Arc<H>,
    pub(super) actor: ApiActor,
}

impl<H> Clone for ApprovalHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            actor: self.actor.clone(),
        }
    }
}

impl<H> ApprovalHttpState<H> {
    /// Wraps one authoritative approval host.
    #[must_use]
    pub fn new(host: H, actor: ApiActor) -> Self {
        Self {
            host: Arc::new(host),
            actor,
        }
    }
}

mod handlers;
mod wire;

/// Builds typed approval routes behind the caller's authentication layers.
pub fn approval_router<H>(state: ApprovalHttpState<H>) -> Router
where
    H: ApprovalQueryHostPort + ApprovalCommandHostPort + 'static,
{
    Router::new()
        .route("/v1/approvals", get(handlers::list_pending::<H>))
        .route(
            "/v1/approvals/{approval_id}",
            get(handlers::get_approval::<H>),
        )
        .route(
            "/v1/approvals/{approval_id}/decision",
            post(handlers::decide::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
