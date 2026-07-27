//! GOCODE HTTP Host
//!
//! Axum-based HTTP/1.1 API host implementing:
//! health, admission, commands, queries, replay, SSE, and auth middleware.

pub mod admission;
pub mod auth;
pub mod commands;
pub mod error;
pub mod health;
pub mod limits;
pub mod middleware;
pub mod queries;
pub mod replay;
pub mod router;
pub mod sse;
