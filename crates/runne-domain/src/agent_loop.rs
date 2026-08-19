//! Durable Agent Loop values and TaskRun-owned replay projections.

use crate::context::ContextManifestRef;
use crate::id::{AttemptId, CycleId, EffectId, IntegrityDigest, StepId, WakeEvidenceId};
use crate::plan::PlanRevisionRef;
use crate::reference::{BudgetReservationRef, ResultRef};
use crate::verification::PlanEvaluationRef;

/// Five normative states of a loop cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoopCycleState {
    Observing,
    Proposing,
    Acting,
    Evaluating,
    Completed,
}

/// Durable outcome of a completed loop cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopDisposition {
    Continue,
    Wait {
        reason: String,
        wake_condition: WakeCondition,
    },
    Complete {
        plan_evaluation_ref: PlanEvaluationRef,
    },
    Fail {
        reason: String,
        unresolved_proposals: Vec<u32>,
    },
}

/// Closed classification of a step outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcomeType {
    Succeeded,
    FailedBeforeCommit,
    FailedAfterCommit,
    Uncertain,
    Cancelled,
}

/// Closed kind of condition that can wake a loop wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeConditionKind {
    ExternalInput,
    Approval,
    ChildTaskRun,
    Timer,
    Reconciliation,
}

/// Authority that produced wake evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeEvidenceSource {
    ExternalInput,
    Approval,
    ChildTaskRun,
    Timer,
    Reconciliation,
}

/// Exact condition committed by a Wait disposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeCondition {
    pub kind: WakeConditionKind,
    pub condition_ref: String,
    pub condition_digest: IntegrityDigest,
}

/// Exact evidence accepted to resume a waiting cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeEvidenceRef {
    pub cycle_id: CycleId,
    pub condition_digest: IntegrityDigest,
    pub source: WakeEvidenceSource,
    pub evidence_id: WakeEvidenceId,
    pub evidence_digest: IntegrityDigest,
    pub observed_at_unix_us: i64,
    pub authority_revision: String,
}

/// Complete replay-safe outcome of one proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepOutcomeRecord {
    pub proposal_index: u32,
    pub step_id: StepId,
    pub outcome_type: StepOutcomeType,
    pub result_ref: Option<ResultRef>,
    pub effect_id: Option<EffectId>,
    pub evidence_digests: Vec<IntegrityDigest>,
}

/// Compact immutable reference to a committed step outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepOutcomeRef {
    pub cycle_id: CycleId,
    pub proposal_index: u32,
    pub step_id: StepId,
    pub outcome_digest: IntegrityDigest,
}

/// One globally unique cycle recorded in TaskRun history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleHistoryEntry {
    pub cycle_id: CycleId,
    pub attempt_id: AttemptId,
    pub sequence: u64,
    pub parent_cycle_id: Option<CycleId>,
}

/// Event-derived projection of the currently active loop cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveLoopCycle {
    pub cycle_id: CycleId,
    pub attempt_id: AttemptId,
    pub sequence: u64,
    pub parent_cycle_id: Option<CycleId>,
    pub state: LoopCycleState,
    pub context_manifest_ref: Option<ContextManifestRef>,
    pub plan_revision_ref: Option<PlanRevisionRef>,
    pub expected_proposal_indexes: Vec<u32>,
    pub recorded_outcomes: Vec<StepOutcomeRecord>,
}

/// Projection of the last completed cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedCycleRef {
    pub cycle_id: CycleId,
    pub attempt_id: AttemptId,
    pub sequence: u64,
    pub disposition: LoopDisposition,
    pub accepted_wake_evidence: Option<WakeEvidenceRef>,
    pub successor_allocated: bool,
}

/// Durable reservation for exactly one successor cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSuccessorCycle {
    pub parent_cycle_id: CycleId,
    pub successor_cycle_id: CycleId,
    pub attempt_id: AttemptId,
    pub sequence: u64,
}

/// Wait projection retained until exact wake evidence is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLoopWait {
    pub cycle_id: CycleId,
    pub wake_condition: WakeCondition,
}

/// Retry projection retained between scheduling and activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRetry {
    pub ordinal: u64,
    pub old_attempt_id: AttemptId,
    pub new_attempt_id: AttemptId,
    pub abandoned_cycle_id: CycleId,
    pub step_outcome_ref: StepOutcomeRef,
    pub due_at_unix_us: i64,
    pub delay_ms: u64,
    pub budget_reservation_ref: BudgetReservationRef,
    pub retry_policy_digest: IntegrityDigest,
}

/// Projection of an in-progress three-event loop checkpoint batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLoopCheckpoint {
    pub checkpoint_id: crate::id::CheckpointId,
    pub start_position: u64,
    pub expected_integrity_digest: IntegrityDigest,
    pub recorded_integrity_digest: Option<IntegrityDigest>,
}

/// Canonical semantic body protected by a loop-checkpoint digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopCheckpointBody {
    pub schema_version: String,
    pub cycle_id: CycleId,
    pub attempt_id: AttemptId,
    pub plan_revision_ref: Option<PlanRevisionRef>,
    pub context_manifest_ref: Option<ContextManifestRef>,
    pub step_outcome_refs: Vec<StepOutcomeRef>,
}

/// Provider-neutral kind of a planner proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalActionType {
    ToolCall,
    SubagentDelegate,
    Wait,
    Complete,
    Fail,
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "018f2e3a-7000-7000-8000-000000000010";

    #[test]
    fn five_states_only() {
        let states = [
            LoopCycleState::Observing,
            LoopCycleState::Proposing,
            LoopCycleState::Acting,
            LoopCycleState::Evaluating,
            LoopCycleState::Completed,
        ];
        assert_eq!(states.len(), 5);
    }

    #[test]
    fn disposition_is_tagged() {
        assert_ne!(
            LoopDisposition::Continue,
            LoopDisposition::Fail {
                reason: "failed".into(),
                unresolved_proposals: vec![],
            }
        );
    }

    #[test]
    fn cycle_starts_in_observing() {
        let cycle = ActiveLoopCycle {
            cycle_id: UUID.parse().unwrap(),
            attempt_id: UUID.parse().unwrap(),
            sequence: 0,
            parent_cycle_id: None,
            state: LoopCycleState::Observing,
            context_manifest_ref: None,
            plan_revision_ref: None,
            expected_proposal_indexes: vec![],
            recorded_outcomes: vec![],
        };
        assert_eq!(cycle.state, LoopCycleState::Observing);
    }

    #[test]
    fn completed_wait_keeps_wake_acceptance_and_successor_fences_separate() {
        let completed = CompletedCycleRef {
            cycle_id: UUID.parse().unwrap(),
            attempt_id: UUID.parse().unwrap(),
            sequence: 2,
            disposition: LoopDisposition::Continue,
            accepted_wake_evidence: None,
            successor_allocated: false,
        };
        assert!(completed.accepted_wake_evidence.is_none());
        assert!(!completed.successor_allocated);
    }

    #[test]
    fn wake_evidence_binds_cycle_condition_source_and_authority() {
        let cycle_id = UUID.parse().unwrap();
        let condition_digest = IntegrityDigest::from_bytes([1; 32]);
        let evidence = WakeEvidenceRef {
            cycle_id,
            condition_digest,
            source: WakeEvidenceSource::Approval,
            evidence_id: UUID.parse().unwrap(),
            evidence_digest: IntegrityDigest::from_bytes([2; 32]),
            observed_at_unix_us: 77,
            authority_revision: "approval-v4".into(),
        };
        assert_eq!(evidence.cycle_id, cycle_id);
        assert_eq!(evidence.condition_digest, condition_digest);
    }

    #[test]
    fn cycle_history_entry_binds_attempt_sequence_and_parent() {
        let entry = CycleHistoryEntry {
            cycle_id: UUID.parse().unwrap(),
            attempt_id: UUID.parse().unwrap(),
            sequence: 0,
            parent_cycle_id: None,
        };
        assert_eq!(entry.sequence, 0);
    }
}
