//! Command input/output DTOs for the TaskRun service.
//!
//! These are the types visible to callers of [`crate::service::TaskRunService`].

use runne_domain::agent_loop::{
    LoopDisposition, StepOutcomeRecord, StepOutcomeRef, WakeEvidenceRef,
};
use runne_domain::command::TerminalResult;
use runne_domain::context::ContextManifestRef;
use runne_domain::conversation::GenerationFailureReason;
use runne_domain::id::{
    AttemptId, CheckpointId, ConversationId, CycleId, IntegrityDigest, StepId, TaskRunId,
    WorkspaceId,
};
use runne_domain::message::MessageText;
use runne_domain::plan::PlanRevisionRef;
use runne_domain::recovery::ReconciliationResultRef;
use runne_domain::reference::{BudgetReservationRef, CheckpointRef};
use runne_domain::task_run::TaskRunState;

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

/// Input for requesting cancellation of an existing task run.
#[derive(Debug, Clone)]
pub struct CancelTaskRunInput {
    /// The task run to cancel.
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
    /// Safe terminal outcome selected after provider-boundary inspection.
    pub completion: ConversationTextCompletion,
}

/// Closed terminal outcome for a started Conversation text execution.
#[derive(Debug, Clone)]
pub enum ConversationTextCompletion {
    /// Validated assistant output may enter canonical state.
    AssistantText(MessageText),
    /// Provider input was rejected after the durable start and before delivery.
    ProhibitedInputRejected {
        /// Closed, non-sensitive rejection reason.
        reason: GenerationFailureReason,
    },
    /// Provider-bound material was rejected without retaining its bytes.
    Rejected {
        /// Closed, non-sensitive rejection reason.
        reason: GenerationFailureReason,
    },
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

include!("commands/outcomes.rs");

#[cfg(test)]
mod tests {
    include!("commands/tests.rs");
}
