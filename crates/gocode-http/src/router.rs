//! Main Axum application router.
//!
//! Composes health (unauthenticated), commands, queries, and replay
//! (protected by auth, request-id, and admission middleware) into a
//! single `Router`.

use axum::{Router, middleware as axum_mw};

use crate::admission::{AdmissionState, admission_middleware};
use crate::auth::AuthLayer;
use crate::commands::{CommandState, command_router};
use crate::health::{HealthState, health_router};
use crate::middleware::request_id_middleware;
use crate::opencode::{OpenCodeSessionState, opencode_session_router};
use crate::queries::{QueryState, query_router};
use crate::replay::{ReplayState, replay_router};

// ── AppState ────────────────────────────────────────────────────────────

/// Bundle of all shared application state.
///
/// Useful for callers that want to hold all pieces together, e.g.
/// the daemon that owns the HTTP host.
#[allow(dead_code)]
pub struct AppState<C, Q, R> {
    pub health_state: HealthState,
    pub admission_state: AdmissionState,
    pub command_state: CommandState<C>,
    pub query_state: QueryState<Q>,
    pub replay_state: ReplayState<R>,
}

// ── create_router ───────────────────────────────────────────────────────

/// Build the full Axum `Router` for the GOCODE HTTP host.
///
/// The returned router includes:
/// - `GET /health` — unauthenticated health endpoint
/// - All command, query, and replay endpoints, protected by:
///   1. `AuthLayer` (bearer token authentication)
///   2. `request_id_middleware` (x-request-id injection)
///   3. `admission_middleware` (recovery-state gating)
pub fn create_router<C, Q, R>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    replay_state: ReplayState<R>,
) -> Router
where
    C: Clone + Send + Sync + 'static,
    Q: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
{
    let auth_layer = AuthLayer::new(token);

    let health = health_router(health_state);

    let protected = Router::new()
        .merge(command_router::<C>())
        .merge(query_router::<Q>())
        .merge(replay_router::<R>(replay_state))
        .layer(axum_mw::from_fn_with_state(
            admission_state.clone(),
            admission_middleware,
        ))
        .layer(axum_mw::from_fn(request_id_middleware))
        .layer(auth_layer);

    Router::new().merge(health).merge(protected)
}

/// Builds the full host with the strict OpenCode V1 session surface included
/// under the same authentication, request identity and admission gates.
pub fn create_router_with_opencode<C, Q, R, H>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    replay_state: ReplayState<R>,
    opencode_state: OpenCodeSessionState<H>,
) -> Router
where
    C: Clone + Send + Sync + 'static,
    Q: Clone + Send + Sync + 'static,
    R: Clone + Send + Sync + 'static,
    H: gocode_opencode_compat::SessionV1HostPort + 'static,
{
    let auth_layer = AuthLayer::new(token);
    let health = health_router(health_state);
    let protected = Router::new()
        .merge(command_router::<C>())
        .merge(query_router::<Q>())
        .merge(replay_router::<R>(replay_state))
        .merge(opencode_session_router(opencode_state))
        .layer(axum_mw::from_fn_with_state(
            admission_state.clone(),
            admission_middleware,
        ))
        .layer(axum_mw::from_fn(request_id_middleware))
        .layer(auth_layer);
    Router::new().merge(health).merge(protected)
}
