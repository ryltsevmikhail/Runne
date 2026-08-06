//! GOCODE HTTP Host
//!
//! Axum-based HTTP/1.1 API host implementing:
//! health, admission, commands, queries, replay, SSE, and auth middleware.

pub mod admission;
pub mod auth;
pub mod commands;
pub mod conversations;
pub mod error;
pub mod health;
pub mod limits;
pub mod local_session;
pub mod middleware;
pub mod opencode;
pub mod operational_telemetry;
pub mod queries;
pub mod replay;
pub mod router;
pub mod runtime_profile;
pub mod secure_local_host;
pub mod sse;
pub mod task_runs;
