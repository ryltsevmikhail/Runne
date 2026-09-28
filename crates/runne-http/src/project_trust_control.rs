//! Protected, explicit Project Trust control endpoints.

use std::sync::Arc;

use axum::{Router, routing::get};
use runne_api::ProjectTrustControlHostPort;

pub struct ProjectTrustControlHttpState<H>(Arc<H>);

impl<H> Clone for ProjectTrustControlHttpState<H> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<H> ProjectTrustControlHttpState<H> {
    pub fn new(host: H) -> Self {
        Self(Arc::new(host))
    }
}

mod handlers;
mod wire;

pub fn project_trust_control_router<H: ProjectTrustControlHostPort + 'static>(
    state: ProjectTrustControlHttpState<H>,
) -> Router {
    Router::new()
        .route(
            "/v1/projects/{project_id}/workspaces/{workspace_id}/trust",
            get(handlers::get_snapshot::<H>).post(handlers::decide::<H>),
        )
        .with_state(state)
}
