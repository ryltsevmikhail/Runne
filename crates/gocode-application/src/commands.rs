//! Command input/output DTOs for the TaskRun service.
//!
//! These are the types visible to callers of [`crate::service::TaskRunService`].

use gocode_domain::agent_loop::{
    LoopDisposition, StepOutcomeRecord, StepOutcomeRef, WakeEvidenceRef,
};
use gocode_domain::command::TerminalResult;
use gocode_domain::context::ContextManifestRef;
use gocode_domain::id::{
    AttemptId, CheckpointId, ConversationId, CycleId, IntegrityDigest, StepId, TaskRunId,
    WorkspaceId,
};
use gocode_domain::message::MessageText;
use gocode_domain::plan::PlanRevisionRef;
use gocode_domain::recovery::ReconciliationResultRef;
use gocode_domain::reference::{BudgetReservationRef, CheckpointRef};
use gocode_domain::task_run::TaskRunState;

/// Input for creating a new task run.
#[derive(Debug, Clone)]
pub struct CreateTaskRunInput {
    /// The conversation this task run belongs to.
    pub conversation_id: ConversationId,
    /// The workspace this task run belongs to.
    pub workspace_id: WorkspaceId,
}

/// Input for queuing a task run for admission.
#[derive(Debug, Clone)]
pub struct QueueTaskRunInput {
    /// The task run to queue.
    pub taskrun_id: TaskRunId,
    /// The version the caller expects (0 for initial queue after create).
    pub expected_version: u64,
}

/// Input for admitting a task run for execution.
#[derive(Debug, Clone)]
pub struct AdmitTaskRunInput {
    /// The task run to admit.
    pub taskrun_id: TaskRunId,
    /// The version the caller expects.
    pub expected_version: u64,
}

/// Input for starting a new execution attempt.
#[derive(Debug, Clone)]
pub struct StartAttemptInput {
    /// The task run to start an attempt on.
    pub taskrun_id: TaskRunId,
    /// The version the caller expects.
    pub expected_version: u64,
}

/// Input for completing a task run.
#[derive(Debug, Clone)]
pub struct CompleteTaskRunInput {
    /// The task run to complete.
    pub taskrun_id: TaskRunId,
    /// The terminal result (success or failure).
    pub result: TerminalResult,
    /// The version the caller expects.
    pub expected_version: u64,
}

/// Input for the durable first phase of a Conversation text execution.
#[derive(Debug, Clone)]
pub struct BeginConversationTextInput {
    /// Target Conversation.
    pub conversation_id: ConversationId,
    /// Conversation version expected before the user message.
    pub expected_version: u64,
    /// Validated user message.
    pub text: MessageText,
}

/// Input for completing a started Conversation text execution.
#[derive(Debug, Clone)]
pub struct FinishConversationTextInput {
    /// Original semantic input, required to revalidate the command fingerprint.
    pub original: BeginConversationTextInput,
    /// Started durable coordination receipt.
    pub started: crate::ports::TextGenerationReceipt,
    /// Deterministic provider output.
    pub assistant_text: MessageText,
}

#[derive(Debug, Clone)]
pub struct StartLoopCycleInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
}

#[derive(Debug, Clone)]
pub struct CommitContextInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
    pub cycle_id: CycleId,
    pub manifest_ref: ContextManifestRef,
}

#[derive(Debug, Clone)]
pub struct CommitPlanInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
    pub cycle_id: CycleId,
    pub plan_revision_ref: PlanRevisionRef,
    pub input_digest: IntegrityDigest,
    pub output_digest: IntegrityDigest,
    pub expected_proposal_indexes: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct RecordStepOutcomeInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
    pub cycle_id: CycleId,
    pub outcome: StepOutcomeRecord,
}

#[derive(Debug, Clone)]
pub struct CompleteLoopCycleInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
    pub cycle_id: CycleId,
    pub disposition: LoopDisposition,
}

#[derive(Debug, Clone)]
pub struct CreateNextCycleInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
    pub parent_cycle_id: CycleId,
}

#[derive(Debug, Clone)]
pub struct ResumeLoopWaitInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
    pub wake_evidence_ref: WakeEvidenceRef,
}

#[derive(Debug, Clone)]
pub struct ScheduleRetryInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
    pub retry_ordinal: u64,
    pub step_outcome_ref: StepOutcomeRef,
    pub retry_policy_digest: IntegrityDigest,
    pub budget_reservation_ref: BudgetReservationRef,
}

#[derive(Debug, Clone)]
pub struct ActivateScheduledRetryInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
    pub retry_ordinal: u64,
}

#[derive(Debug, Clone)]
pub struct CommitRecoveryResumeInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
    pub context_manifest_ref: ContextManifestRef,
    pub checkpoint_ref: CheckpointRef,
    pub reconciliation_ref: ReconciliationResultRef,
}

#[derive(Debug, Clone)]
pub struct CommitLoopCheckpointInput {
    pub taskrun_id: TaskRunId,
    pub expected_version: u64,
    pub cycle_id: CycleId,
    pub attempt_id: AttemptId,
    pub schema_version: String,
    pub plan_revision_ref: Option<PlanRevisionRef>,
    pub context_manifest_ref: Option<ContextManifestRef>,
    pub step_outcome_refs: Vec<StepOutcomeRef>,
}

/// The outcome of a successfully processed command.
///
/// Returned to the caller after the command is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    /// A task run was created.
    TaskRunCreated {
        /// The ID of the newly created task run.
        taskrun_id: TaskRunId,
        /// The new stream version (always 1).
        new_version: u64,
    },
    /// A task run was queued for admission.
    TaskRunQueued {
        /// The task run ID.
        taskrun_id: TaskRunId,
        /// The new stream version.
        new_version: u64,
    },
    /// A task run was admitted for execution.
    TaskRunAdmitted {
        /// The task run ID.
        taskrun_id: TaskRunId,
        /// The new stream version.
        new_version: u64,
    },
    /// A new attempt was started.
    AttemptStarted {
        /// The task run ID.
        taskrun_id: TaskRunId,
        /// The newly generated attempt ID.
        attempt_id: AttemptId,
        /// The new stream version.
        new_version: u64,
    },
    /// A task run was completed with a terminal result.
    TaskRunCompleted {
        /// The task run ID.
        taskrun_id: TaskRunId,
        /// The new stream version.
        new_version: u64,
    },
    CycleStarted {
        taskrun_id: TaskRunId,
        cycle_id: CycleId,
        new_version: u64,
    },
    ContextCommitted {
        taskrun_id: TaskRunId,
        cycle_id: CycleId,
        new_version: u64,
    },
    PlanCommitted {
        taskrun_id: TaskRunId,
        plan_ref: Box<PlanRevisionRef>,
        new_version: u64,
    },
    StepOutcomeRecorded {
        taskrun_id: TaskRunId,
        step_id: StepId,
        new_version: u64,
    },
    LoopDispositionCommitted {
        taskrun_id: TaskRunId,
        cycle_id: CycleId,
        final_state: TaskRunState,
        new_version: u64,
    },
    NextCycleAllocated {
        taskrun_id: TaskRunId,
        successor_cycle_id: CycleId,
        new_version: u64,
    },
    LoopWaitResumed {
        taskrun_id: TaskRunId,
        cycle_id: CycleId,
        new_version: u64,
    },
    RetryScheduled {
        taskrun_id: TaskRunId,
        new_attempt_id: AttemptId,
        due_at_unix_us: i64,
        new_version: u64,
    },
    RetryActivated {
        taskrun_id: TaskRunId,
        attempt_id: AttemptId,
        new_version: u64,
    },
    RecoveryResumed {
        taskrun_id: TaskRunId,
        attempt_id: AttemptId,
        new_version: u64,
    },
    LoopCheckpointCommitted {
        taskrun_id: TaskRunId,
        checkpoint_id: CheckpointId,
        event_position: u64,
        new_version: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_UUID: &str = "018f2e3a-7000-7000-8000-000000000000";

    #[test]
    fn test_command_outcome_clone_eq() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let c1 = CommandOutcome::TaskRunCreated {
            taskrun_id: tr_id,
            new_version: 1,
        };
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_command_outcome_attempt_started_holds_attempt_id() {
        let tr_id: TaskRunId = VALID_UUID.parse().unwrap();
        let att_id: AttemptId = "018f2e3a-7000-7000-8000-000000000001".parse().unwrap();
        let outcome = CommandOutcome::AttemptStarted {
            taskrun_id: tr_id,
            attempt_id: att_id,
            new_version: 4,
        };
        if let CommandOutcome::AttemptStarted { attempt_id, .. } = &outcome {
            assert_eq!(*attempt_id, att_id);
        } else {
            panic!("expected AttemptStarted");
        }
    }
}
