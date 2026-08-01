//! Production Axum router composition.
//!
//! Only implemented canonical routes are mounted. Legacy command, query and
//! replay stubs remain outside this production surface.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Router, middleware as axum_mw};
use gocode_api::{
    ConversationCommandHostPort, ConversationQueryHostPort, TaskRunCommandHostPort,
    TaskRunQueryHostPort,
};

use crate::admission::{AdmissionState, admission_middleware};
use crate::auth::{AuthLayer, SessionAuthLayer};
use crate::conversations::{ConversationHttpState, conversation_router};
use crate::health::{HealthState, health_router};
use crate::local_session::{LocalSessionHttpState, VerifiedLocalTls, local_session_router};
use crate::middleware::request_id_middleware;
use crate::opencode::{OpenCodeSessionState, opencode_session_router};
use crate::replay::{ReplayHttpState, replay_router};
use crate::runtime_profile::{
    RuntimeProfileHttpState, runtime_profile_router, runtime_profile_session_router,
};
use crate::task_runs::{TaskRunHttpState, task_run_router};

include!("router_parts/production.rs");

#[cfg(test)]
mod tests {
    include!("router_parts/tests_support.rs");
    include!("router_parts/tests.rs");
}
