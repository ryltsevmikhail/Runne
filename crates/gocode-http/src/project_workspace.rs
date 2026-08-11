//! Strict authenticated HTTP projection of canonical Project and Workspace hosts.

use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use gocode_api::{ApiActor, ProjectWorkspaceCommandHostPort, ProjectWorkspaceQueryHostPort};

const MAX_PROJECT_WORKSPACE_BODY_BYTES: usize = 16 * 1024;

/// Shared Project/Workspace HTTP host state.
pub struct ProjectWorkspaceHttpState<H> {
    pub(super) host: Arc<H>,
    pub(super) actor: ApiActor,
}

impl<H> Clone for ProjectWorkspaceHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            actor: self.actor.clone(),
        }
    }
}

impl<H> ProjectWorkspaceHttpState<H> {
    /// Wraps the public canonical host and fixes this adapter's event actor.
    pub fn new(host: H, actor: ApiActor) -> Self {
        Self {
            host: Arc::new(host),
            actor,
        }
    }
}

mod handlers;
mod wire;

/// Builds every authenticated Project/Workspace route in the v1 contract wave.
pub fn project_workspace_router<H>(state: ProjectWorkspaceHttpState<H>) -> Router
where
    H: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort + 'static,
{
    Router::new()
        .route(
            "/v1/projects",
            get(handlers::list_projects::<H>).post(handlers::create_project::<H>),
        )
        .route(
            "/v1/projects/{project_id}",
            get(handlers::get_project::<H>).delete(handlers::delete_project::<H>),
        )
        .route(
            "/v1/projects/{project_id}/archive",
            post(handlers::archive_project::<H>),
        )
        .route(
            "/v1/projects/{project_id}/restore",
            post(handlers::restore_project::<H>),
        )
        .route(
            "/v1/projects/{project_id}/workspaces",
            get(handlers::list_workspaces::<H>).post(handlers::create_workspace::<H>),
        )
        .route(
            "/v1/workspaces/{workspace_id}",
            get(handlers::get_workspace::<H>),
        )
        .route(
            "/v1/workspaces/{workspace_id}/open",
            post(handlers::open_workspace::<H>),
        )
        .route(
            "/v1/workspaces/{workspace_id}/root-bindings",
            post(handlers::bind_workspace_root::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_PROJECT_WORKSPACE_BODY_BYTES))
        .with_state(state)
}
