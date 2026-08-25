//! Authenticated HTTP projection of runtime-owned process lifecycle.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use runne_api::ProcessHostPort;
use std::sync::Arc;

const MAX_BODY_BYTES: usize = 16 * 1024;

/// Shared process host state and bounded actor identity.
pub struct ProcessHttpState<H> {
    pub(super) host: Arc<H>,
    pub(super) actor: runne_api::ApiActor,
}

impl<H> Clone for ProcessHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            actor: self.actor.clone(),
        }
    }
}

impl<H> ProcessHttpState<H> {
    /// Creates process state for one runtime-owned provider.
    #[must_use]
    pub fn new(host: H, actor: runne_api::ApiActor) -> Self {
        Self {
            host: Arc::new(host),
            actor,
        }
    }
}

mod handlers;
mod wire;

/// Builds typed process lifecycle routes behind the caller's auth layers.
pub fn process_router<H>(state: ProcessHttpState<H>) -> Router
where
    H: ProcessHostPort + 'static,
{
    Router::new()
        .route("/v1/processes", post(handlers::start_process::<H>))
        .route(
            "/v1/processes/{process_id}",
            get(handlers::get_process::<H>),
        )
        .route(
            "/v1/processes/{process_id}/output",
            get(handlers::read_output::<H>),
        )
        .route(
            "/v1/processes/{process_id}/stop",
            post(handlers::stop_process::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
