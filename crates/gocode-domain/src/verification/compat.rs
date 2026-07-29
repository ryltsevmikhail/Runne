//! Compatibility types retained from the pre-merge `verification` module
//! to keep `agent_loop` and `task_run` compiling without structural changes.

use crate::id::{IntegrityDigest, PlanEvaluationId, PlanId, TaskRunId};

/// Plan evaluation reference (pre-merge compatibility type).
///
/// Retained for `agent_loop::LoopDisposition::Complete`,
/// `task_run::validate_cycle_completion`, and `gocode_application`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEvaluationRef {
    /// Unique plan evaluation identifier.
    pub evaluation_id: PlanEvaluationId,
    /// Owning task run.
    pub taskrun_id: TaskRunId,
    /// Evaluated plan identity.
    pub plan_id: PlanId,
    /// Plan revision that was evaluated.
    pub plan_revision: u64,
    /// Stream head position at evaluation time.
    pub evaluated_stream_head: u64,
    /// Aggregated evaluation result.
    pub result: PlanEvaluationResult,
    /// Digest of gate definitions used in this evaluation.
    pub gate_definitions_digest: IntegrityDigest,
    /// Digest of the evidence set used in this evaluation.
    pub evidence_set_digest: IntegrityDigest,
    /// Digest of the full evaluation output.
    pub evaluation_digest: IntegrityDigest,
}

/// Plan evaluation result discriminant (pre-merge compatibility type).
///
/// Retained for `task_run::validate_cycle_completion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanEvaluationResult {
    /// All gates passed.
    Passed,
    /// At least one gate failed.
    Failed,
    /// At least one gate blocked (evidence incomplete).
    Blocked,
    /// Requires human review.
    RequiresReview,
}
