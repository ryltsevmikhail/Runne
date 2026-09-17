//! Silent production twin of `writer_stage_live`.
//!
//! In production builds the broker keeps its exact audited call shape, so
//! every stage function exists here as a no-op. This module must contain no
//! emission sink at all; the source-policy test keeps it sink-free.

/// Marks the fd 3 secret-slot inspection stage (silent in production).
pub const fn secret_inspect() {}

/// Marks the daemon endpoint handoff receive stage (silent in production).
pub const fn endpoint_receive() {}

/// Marks the pinned writer session observation stage (silent in production).
pub const fn session_observe() {}

/// Marks the authenticated writer execution stage (silent in production).
pub const fn authenticated_run() {}

/// Reports that the fd 3 secret-slot inspection stage failed (silent).
pub const fn secret_inspect_failed() {}

/// Reports that the daemon endpoint handoff receive stage failed (silent).
pub const fn endpoint_receive_failed() {}

/// Reports that the pinned writer session observation stage failed (silent).
pub const fn session_observe_failed() {}

/// Reports that the authenticated writer execution stage failed (silent).
pub const fn authenticated_run_failed() {}
