//! Strict authenticated HTTP projection of canonical Project and Workspace hosts.

use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    response::Response,
    routing::{get, post},
};
use gocode_api::{ApiActor, ProjectWorkspaceCommandHostPort, ProjectWorkspaceQueryHostPort};

use crate::error::{RequestId, canonical_error_response};

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
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(MAX_PROJECT_WORKSPACE_BODY_BYTES))
        .layer(middleware::from_fn(body_limit_middleware))
        .with_state(state)
}

async fn method_not_allowed(request: axum::extract::Request) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(RequestId::generate);
    canonical_error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        &request_id,
    )
}

async fn body_limit_middleware(
    request: axum::extract::Request,
    next: middleware::Next,
) -> Response {
    if request
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_PROJECT_WORKSPACE_BODY_BYTES)
    {
        let request_id = request
            .extensions()
            .get::<RequestId>()
            .cloned()
            .unwrap_or_else(RequestId::generate);
        return canonical_error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            &request_id,
        );
    }
    next.run(request).await
}
