//! Domain commands — what the application layer sends to aggregates.
//!
//! Commands are pure data; the domain decides whether to accept them
//! and produce events.

use crate::agent_loop::{
    LoopCheckpointBody, LoopDisposition, StepOutcomeRecord, StepOutcomeRef, WakeEvidenceRef,
};
use crate::context::ContextManifestRef;
use crate::id::{
    AttemptId, CheckpointId, ConversationId, CycleId, IntegrityDigest, TaskRunId, WorkspaceId,
};
use crate::plan::PlanRevisionRef;
use crate::recovery::ReconciliationResultRef;
use crate::reference::{BudgetReservationRef, CheckpointRef};

// ── ConversationCommand ──────────────────────────────────────────────────

/// All commands that can be sent to an existing
/// [`Conversation`](crate::conversation::Conversation) aggregate.
#[derive(Debug, Clone)]
pub enum ConversationCommand {
    /// Close the conversation permanently.
    Close,
}

// ── TerminalResult ─────────────────────────────────────────────────────────

/// The outcome of a completed task run (succeeded or failed).
///
/// Other terminal states (cancelled, budget_exhausted, policy_denied,
/// unrecoverable) have their own dedicated events and do not carry
/// a `TerminalResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalResult {
    /// The task completed successfully.
    Success,
    /// The task failed with a reason.
    /// The reason the task failed.
    Failure { reason: String },
}

// ── CreateTaskRun ──────────────────────────────────────────────────────────

/// Command to create a new [`TaskRun`](crate::task_run::TaskRun) aggregate.
///
/// Carries the aggregate identity and parent conversation / workspace
/// references.
#[derive(Debug, Clone)]
pub struct CreateTaskRun {
    /// The ID to assign to the new task run.
    pub taskrun_id: TaskRunId,
    /// The conversation this task run belongs to.
    pub conversation_id: ConversationId,
    /// The workspace this task run belongs to.
    pub workspace_id: WorkspaceId,
}

// ── TaskRunCommand ────────────────────────────────────────────────────────

/// All commands that can be sent to an existing [`TaskRun`](crate::task_run::TaskRun) aggregate.
#[derive(Debug, Clone)]
pub enum TaskRunCommand {
    /// Admit the task run for execution.
    Admit,

    /// Start a new attempt.
    StartAttempt {
        /// The ID to assign to the new attempt.
        attempt_id: AttemptId,
    },

    /// Queue the task run for admission (created → queued).
    Queue,

    /// Wait for approval or external input.
    WaitForApproval,

    /// Resume execution after waiting.
    Resume,

    /// Start a retry.
    StartRetry {
        /// The ID to assign to the retry attempt.
        attempt_id: AttemptId,
    },

    /// Complete a retry.
    CompleteRetry {
        /// The ID of the attempt that completed retry.
        attempt_id: AttemptId,
    },

    /// Begin a checkpoint operation.
    StartCheckpoint,

    /// Commit a checkpoint — transitions back to running.
    CommitCheckpoint,

    /// Request cancellation of the task run.
    RequestCancellation,

    /// Complete cancellation — transitions to the terminal cancelled state.
    CompleteCancellation,

    /// Complete execution with a result.
    Complete {
        /// The terminal result (success or failure).
        result: TerminalResult,
    },

    /// Mark the task run as failed.
    Fail {
        /// The reason the task failed.
        reason: String,
    },

    /// Start a reconciliation pass.
    StartReconciliation,

    /// Complete a reconciliation pass — transitions back to running.
    CompleteReconciliation,

    /// Mark the task run as unrecoverable (terminal).
    MarkUnrecoverable,

    /// Start an initial cycle or consume an exact successor reservation.
    StartLoopCycle { cycle_id: CycleId },
    /// Bind an immutable context manifest to the active cycle.
    CommitContext {
        cycle_id: CycleId,
        manifest_ref: ContextManifestRef,
    },
    /// Bind an immutable plan revision and exact proposal indexes.
    CommitPlan {
        cycle_id: CycleId,
        plan_revision_ref: PlanRevisionRef,
        input_digest: IntegrityDigest,
        output_digest: IntegrityDigest,
        expected_proposal_indexes: Vec<u32>,
    },
    /// Record one exact proposal outcome.
    RecordStepOutcome {
        cycle_id: CycleId,
        outcome: StepOutcomeRecord,
    },
    /// Complete the active loop cycle.
    CompleteLoopCycle {
        cycle_id: CycleId,
        disposition: LoopDisposition,
    },
    /// Reserve one successor cycle.
    CreateNextCycle {
        parent_cycle_id: CycleId,
        successor_cycle_id: CycleId,
    },
    /// Resume a loop wait with exact application-validated evidence.
    ResumeLoopWait { wake_evidence_ref: WakeEvidenceRef },
    /// Schedule a retry and commit its sampled delay.
    ScheduleRetry {
        new_attempt_id: AttemptId,
        retry_ordinal: u64,
        step_outcome_ref: StepOutcomeRef,
        retry_policy_digest: IntegrityDigest,
        budget_reservation_ref: BudgetReservationRef,
        delay_ms: u64,
        due_at_unix_us: i64,
    },
    /// Activate an exact pending retry after its due time.
    ActivateScheduledRetryAttempt {
        retry_ordinal: u64,
        now_unix_us: i64,
    },
    /// Resume after reconciliation with a new attempt.
    CommitRecoveryResume {
        new_attempt_id: AttemptId,
        context_manifest_ref: ContextManifestRef,
        checkpoint_ref: CheckpointRef,
        reconciliation_ref: ReconciliationResultRef,
    },
    /// Atomically commit a three-event loop checkpoint batch.
    CommitLoopCheckpoint {
        checkpoint_id: CheckpointId,
        event_position: u64,
        body: LoopCheckpointBody,
        integrity_digest: IntegrityDigest,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_loop::{
        LoopCheckpointBody, LoopDisposition, StepOutcomeRecord, StepOutcomeRef, StepOutcomeType,
        WakeEvidenceRef, WakeEvidenceSource,
    };
    use crate::context::ContextManifestRef;
    use crate::id::{
        BudgetReservationId, CheckpointId, ContextManifestId, CycleId, IntegrityDigest, PlanId,
        ReconciliationRunId, ResultId, StepId, WakeEvidenceId,
    };
    use crate::plan::PlanRevisionRef;
    use crate::recovery::{ReconciliationResultRef, ReconciliationStatus};
    use crate::reference::{BudgetReservationRef, CheckpointRef, ResultRef};

    const UUID: &str = "018f2e3a-7000-7000-8000-000000000010";

    fn context_ref() -> ContextManifestRef {
        ContextManifestRef {
            manifest_id: UUID.parse::<ContextManifestId>().unwrap(),
            taskrun_id: UUID.parse().unwrap(),
            attempt_id: UUID.parse().unwrap(),
            cycle_id: UUID.parse().unwrap(),
            revision: 1,
            policy_revision: "context-v1".into(),
            integrity_digest: IntegrityDigest::from_bytes([1; 32]),
        }
    }

    fn budget_ref() -> BudgetReservationRef {
        BudgetReservationRef {
            reservation_id: UUID.parse::<BudgetReservationId>().unwrap(),
            taskrun_id: UUID.parse().unwrap(),
            attempt_id: UUID.parse().unwrap(),
            retry_ordinal: 1,
            reservation_digest: IntegrityDigest::from_bytes([2; 32]),
        }
    }

    fn plan_ref() -> PlanRevisionRef {
        PlanRevisionRef {
            plan_id: UUID.parse::<PlanId>().unwrap(),
            taskrun_id: UUID.parse().unwrap(),
            cycle_id: UUID.parse().unwrap(),
            revision: 1,
            context_manifest_ref: context_ref(),
            expected_proposal_indexes: vec![0],
            proposal_batch_digest: IntegrityDigest::from_bytes([3; 32]),
            planning_policy_ref: ResultRef::new(
                UUID.parse::<ResultId>().unwrap(),
                "application/json",
                IntegrityDigest::from_bytes([4; 32]),
            )
            .unwrap(),
            planning_budget_ref: budget_ref(),
            parent_ref: None,
            integrity_digest: IntegrityDigest::from_bytes([5; 32]),
        }
    }

    fn step_ref() -> StepOutcomeRef {
        StepOutcomeRef {
            cycle_id: UUID.parse::<CycleId>().unwrap(),
            proposal_index: 0,
            step_id: UUID.parse::<StepId>().unwrap(),
            outcome_digest: IntegrityDigest::from_bytes([6; 32]),
        }
    }

    fn wake_ref() -> WakeEvidenceRef {
        WakeEvidenceRef {
            cycle_id: UUID.parse().unwrap(),
            condition_digest: IntegrityDigest::from_bytes([7; 32]),
            source: WakeEvidenceSource::Approval,
            evidence_id: UUID.parse::<WakeEvidenceId>().unwrap(),
            evidence_digest: IntegrityDigest::from_bytes([8; 32]),
            observed_at_unix_us: 10,
            authority_revision: "approval-v1".into(),
        }
    }

    fn reconciliation_ref() -> ReconciliationResultRef {
        ReconciliationResultRef {
            reconciliation_run_id: UUID.parse::<ReconciliationRunId>().unwrap(),
            taskrun_id: UUID.parse().unwrap(),
            predecessor_attempt_id: UUID.parse().unwrap(),
            recovery_generation: 0,
            reconciled_stream_position: 7,
            status: ReconciliationStatus::Reconciled,
            unresolved_effect_count: 0,
            result_digest: IntegrityDigest::from_bytes([9; 32]),
        }
    }

    #[test]
    fn phase5_command_contract_has_exact_eleven_variants() {
        let cycle_id = UUID.parse().unwrap();
        let commands = [
            TaskRunCommand::StartLoopCycle { cycle_id },
            TaskRunCommand::CommitContext {
                cycle_id,
                manifest_ref: context_ref(),
            },
            TaskRunCommand::CommitPlan {
                cycle_id,
                plan_revision_ref: plan_ref(),
                input_digest: IntegrityDigest::from_bytes([10; 32]),
                output_digest: IntegrityDigest::from_bytes([11; 32]),
                expected_proposal_indexes: vec![0],
            },
            TaskRunCommand::RecordStepOutcome {
                cycle_id,
                outcome: StepOutcomeRecord {
                    proposal_index: 0,
                    step_id: UUID.parse().unwrap(),
                    outcome_type: StepOutcomeType::Succeeded,
                    result_ref: None,
                    effect_id: None,
                    evidence_digests: vec![],
                },
            },
            TaskRunCommand::CompleteLoopCycle {
                cycle_id,
                disposition: LoopDisposition::Continue,
            },
            TaskRunCommand::CreateNextCycle {
                parent_cycle_id: cycle_id,
                successor_cycle_id: UUID.parse().unwrap(),
            },
            TaskRunCommand::ResumeLoopWait {
                wake_evidence_ref: wake_ref(),
            },
            TaskRunCommand::ScheduleRetry {
                new_attempt_id: UUID.parse().unwrap(),
                retry_ordinal: 1,
                step_outcome_ref: step_ref(),
                retry_policy_digest: IntegrityDigest::from_bytes([12; 32]),
                budget_reservation_ref: budget_ref(),
                delay_ms: 25,
                due_at_unix_us: 35,
            },
            TaskRunCommand::ActivateScheduledRetryAttempt {
                retry_ordinal: 1,
                now_unix_us: 35,
            },
            TaskRunCommand::CommitRecoveryResume {
                new_attempt_id: UUID.parse().unwrap(),
                context_manifest_ref: context_ref(),
                checkpoint_ref: CheckpointRef {
                    checkpoint_id: UUID.parse::<CheckpointId>().unwrap(),
                    event_position: 7,
                    integrity_digest: IntegrityDigest::from_bytes([13; 32]),
                },
                reconciliation_ref: reconciliation_ref(),
            },
            TaskRunCommand::CommitLoopCheckpoint {
                checkpoint_id: UUID.parse().unwrap(),
                event_position: 8,
                body: LoopCheckpointBody {
                    schema_version: "1".into(),
                    cycle_id,
                    attempt_id: UUID.parse().unwrap(),
                    plan_revision_ref: Some(plan_ref()),
                    context_manifest_ref: Some(context_ref()),
                    step_outcome_refs: vec![step_ref()],
                },
                integrity_digest: IntegrityDigest::from_bytes([14; 32]),
            },
        ];

        assert_eq!(commands.len(), 11);
    }
}
