//! Production Axum router composition.
//!
//! Only implemented canonical routes are mounted. Legacy command, query and
//! replay stubs remain outside this production surface.

use axum::{Router, middleware as axum_mw};
use gocode_api::{
    ConversationCommandHostPort, ConversationQueryHostPort, TaskRunCommandHostPort,
    TaskRunQueryHostPort,
};

use crate::admission::{AdmissionState, admission_middleware};
use crate::auth::AuthLayer;
use crate::conversations::{ConversationHttpState, conversation_router};
use crate::health::{HealthState, health_router};
use crate::middleware::request_id_middleware;
use crate::opencode::{OpenCodeSessionState, opencode_session_router};
use crate::replay::{ReplayHttpState, replay_router};
use crate::runtime_profile::{RuntimeProfileHttpState, runtime_profile_router};
use crate::task_runs::{TaskRunHttpState, task_run_router};

/// Builds the production canonical HTTP surface.
///
/// `/health` remains unauthenticated. Every `/v1/task-runs/*` route is wrapped
/// by one request identity, bearer authentication, and admission gating.
pub fn create_router<H>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<H>,
) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    let protected = protected_task_run_router(token, admission_state, task_run_state);
    Router::new()
        .merge(health_router(health_state))
        .merge(protected)
}

/// Builds the production canonical TaskRun and Conversation message surface.
pub fn create_router_with_conversations<T, C>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<T>,
    conversation_state: ConversationHttpState<C>,
    runtime_profile_state: RuntimeProfileHttpState,
    replay_state: ReplayHttpState,
) -> Router
where
    T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
    C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
{
    let protected = Router::new()
        .merge(runtime_profile_router(runtime_profile_state))
        .merge(task_run_router(task_run_state))
        .merge(conversation_router(conversation_state))
        .merge(replay_router(replay_state))
        .layer(axum_mw::from_fn_with_state(
            admission_state,
            admission_middleware,
        ))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new()
        .merge(health_router(health_state))
        .merge(protected)
}

/// Builds the canonical surface plus the pinned OpenCode V1 compatibility
/// routes under the same protection contour.
pub fn create_router_with_opencode<T, O>(
    token: [u8; 32],
    health_state: HealthState,
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<T>,
    opencode_state: OpenCodeSessionState<O>,
) -> Router
where
    T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
    O: gocode_opencode_compat::SessionV1HostPort + 'static,
{
    let protected = Router::new()
        .merge(task_run_router(task_run_state))
        .merge(opencode_session_router(opencode_state))
        .layer(axum_mw::from_fn_with_state(
            admission_state,
            admission_middleware,
        ))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware));
    Router::new()
        .merge(health_router(health_state))
        .merge(protected)
}

fn protected_task_run_router<H>(
    token: [u8; 32],
    admission_state: AdmissionState,
    task_run_state: TaskRunHttpState<H>,
) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    task_run_router(task_run_state)
        .layer(axum_mw::from_fn_with_state(
            admission_state,
            admission_middleware,
        ))
        .layer(AuthLayer::new(token))
        .layer(axum_mw::from_fn(request_id_middleware))
}
