//! Recovery domain types — reconciliation result references.
//!
//! ReconciliationResultRef provides durable proof that reconciliation
//! completed successfully before recovery resume.

use crate::id::{AttemptId, IntegrityDigest, ReconciliationRunId, TaskRunId};

// ── ReconciliationResultRef ─────────────────────────────────────────────

/// Durable proof of completed reconciliation.
///
/// This type is domain-located so that TaskRunCommand can reference it
/// without depending upward on application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationResultRef {
    /// Unique reconciliation run identifier.
    pub reconciliation_run_id: ReconciliationRunId,
    /// TaskRun that was reconciled.
    pub taskrun_id: TaskRunId,
    /// Attempt that was active before reconciliation.
    pub predecessor_attempt_id: AttemptId,
    /// Monotonic recovery generation.
    pub recovery_generation: u64,
    /// Stream position at which reconciliation was evaluated.
    pub reconciled_stream_position: u64,
    /// Terminal reconciliation status.
    pub status: ReconciliationStatus,
    /// Number of unresolved effects (must be 0 for resume).
    pub unresolved_effect_count: u64,
    /// Integrity digest of the reconciliation result.
    pub result_digest: IntegrityDigest,
}

// ── ReconciliationStatus ────────────────────────────────────────────────

/// Status of a reconciliation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationStatus {
    /// All effects reconciled successfully.
    Reconciled,
    /// Reconciliation failed.
    Failed,
    /// Reconciliation is still in progress.
    InProgress,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ReconciliationRunId;

    const UUID: &str = "018f2e3a-7000-7000-8000-000000000010";

    #[test]
    fn reconciliation_ref_uses_typed_run_identity_and_exact_head() {
        let reference = ReconciliationResultRef {
            reconciliation_run_id: UUID.parse::<ReconciliationRunId>().unwrap(),
            taskrun_id: UUID.parse().unwrap(),
            predecessor_attempt_id: UUID.parse().unwrap(),
            recovery_generation: 4,
            reconciled_stream_position: 91,
            status: ReconciliationStatus::Reconciled,
            unresolved_effect_count: 0,
            result_digest: IntegrityDigest::from_bytes([5; 32]),
        };

        assert_eq!(reference.recovery_generation, 4);
        assert_eq!(reference.reconciled_stream_position, 91);
    }
}
