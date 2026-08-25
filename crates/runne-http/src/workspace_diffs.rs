//! Authenticated HTTP projection of bounded Workspace changes and diffs.

use axum::{Router, extract::DefaultBodyLimit, routing::get};
use runne_api::WorkspaceDiffHostPort;
use std::sync::Arc;

const MAX_BODY_BYTES: usize = 16 * 1024;

pub struct WorkspaceDiffHttpState<H> {
    pub(super) host: Arc<H>,
}

impl<H> Clone for WorkspaceDiffHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
        }
    }
}

impl<H> WorkspaceDiffHttpState<H> {
    #[must_use]
    pub fn new(host: H) -> Self {
        Self {
            host: Arc::new(host),
        }
    }
}

mod handlers;
mod wire;

pub fn workspace_diff_router<H>(state: WorkspaceDiffHttpState<H>) -> Router
where
    H: WorkspaceDiffHostPort + 'static,
{
    Router::new()
        .route(
            "/v1/workspaces/{workspace_id}/changes",
            get(handlers::list_changes::<H>),
        )
        .route(
            "/v1/workspaces/{workspace_id}/diff",
            get(handlers::read_diff::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
