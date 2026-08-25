//! Authenticated HTTP projection of bounded Workspace file queries.

use axum::{Router, extract::DefaultBodyLimit, routing::get};
use runne_api::WorkspaceFileHostPort;
use std::sync::Arc;

const MAX_BODY_BYTES: usize = 16 * 1024;

pub struct WorkspaceFileHttpState<H> {
    pub(super) host: Arc<H>,
}

impl<H> Clone for WorkspaceFileHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
        }
    }
}

impl<H> WorkspaceFileHttpState<H> {
    #[must_use]
    pub fn new(host: H) -> Self {
        Self {
            host: Arc::new(host),
        }
    }
}

mod handlers;
mod wire;

pub fn workspace_file_router<H>(state: WorkspaceFileHttpState<H>) -> Router
where
    H: WorkspaceFileHostPort + 'static,
{
    Router::new()
        .route(
            "/v1/workspaces/{workspace_id}/files",
            get(handlers::list_files::<H>),
        )
        .route(
            "/v1/workspaces/{workspace_id}/files/content",
            get(handlers::read_file::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
