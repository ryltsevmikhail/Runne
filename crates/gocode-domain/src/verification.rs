//! Replay-safe references to authoritative verification results.

use crate::id::{IntegrityDigest, PlanEvaluationId, PlanId, TaskRunId};

/// Closed result of an authoritative plan evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanEvaluationResult {
    /// All required gates passed.
    Passed,
    /// At least one required gate failed.
    Failed,
    /// Evaluation could not complete.
    Blocked,
    /// Human or policy review is required.
    RequiresReview,
}

/// Replay-safe binding to an authoritative plan evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEvaluationRef {
    /// Evaluation identity.
    pub evaluation_id: PlanEvaluationId,
    /// Owning task run.
    pub taskrun_id: TaskRunId,
    /// Evaluated plan identity.
    pub plan_id: PlanId,
    /// Exact evaluated plan revision.
    pub plan_revision: u64,
    /// TaskRun stream head against which evaluation was produced.
    pub evaluated_stream_head: u64,
    /// Closed evaluation result.
    pub result: PlanEvaluationResult,
    /// Digest of the exact gate definitions.
    pub gate_definitions_digest: IntegrityDigest,
    /// Digest of the exact evidence set.
    pub evidence_set_digest: IntegrityDigest,
    /// Digest of the complete evaluation.
    pub evaluation_digest: IntegrityDigest,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::IntegrityDigest;

    const UUID: &str = "018f2e3a-7000-7000-8000-000000000010";

    #[test]
    fn plan_evaluation_ref_binds_owner_plan_head_and_result() {
        let reference = PlanEvaluationRef {
            evaluation_id: UUID.parse::<PlanEvaluationId>().unwrap(),
            taskrun_id: UUID.parse::<TaskRunId>().unwrap(),
            plan_id: UUID.parse::<PlanId>().unwrap(),
            plan_revision: 3,
            evaluated_stream_head: 41,
            result: PlanEvaluationResult::Passed,
            gate_definitions_digest: IntegrityDigest::from_bytes([1; 32]),
            evidence_set_digest: IntegrityDigest::from_bytes([2; 32]),
            evaluation_digest: IntegrityDigest::from_bytes([3; 32]),
        };

        assert_eq!(reference.result, PlanEvaluationResult::Passed);
        assert_eq!(reference.evaluated_stream_head, 41);
    }
}
