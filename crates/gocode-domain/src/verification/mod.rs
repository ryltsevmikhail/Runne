//! Verification domain types — pure, no async, no IO.

pub mod backup;
pub mod compat;
pub mod digest;
pub mod evaluation;
pub mod evidence;
pub mod identity;
pub mod intent;
pub mod plan;
pub mod profile;
pub mod run;
pub mod runner;

// Re-export pre-merge compatibility types so that `agent_loop` and
// `task_run` continue to compile without structural changes.
pub use compat::{PlanEvaluationRef, PlanEvaluationResult};
