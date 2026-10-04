//! Domain commands — what the application layer sends to aggregates.
//!
//! Commands are pure data; the domain decides whether to accept them
//! and produce events.

use crate::agent_loop::{
    LoopCheckpointBody, LoopDisposition, StepOutcomeRecord, StepOutcomeRef, WakeEvidenceRef,
};
use crate::context::ContextManifestRef;
use crate::conversation::GenerationFailureReason;
use crate::id::{
    AttemptId, CheckpointId, ConversationId, CycleId, IntegrityDigest, MessageId, TaskRunId,
    WorkspaceId,
};
use crate::message::MessageText;
use crate::plan::PlanRevisionRef;
use crate::recovery::ReconciliationResultRef;
use crate::reference::{BudgetReservationRef, CheckpointRef};

// ── ConversationCommand ──────────────────────────────────────────────────

/// All commands that can be sent to an existing
/// [`Conversation`](crate::conversation::Conversation) aggregate.
#[derive(Debug, Clone)]
pub enum ConversationCommand {
    /// Append a user message and durably bind it to a running execution.
    AppendUserMessage {
        /// Server-generated message identity.
        message_id: MessageId,
        /// Coordinating TaskRun.
        taskrun_id: TaskRunId,
        /// Exact active attempt.
        attempt_id: AttemptId,
        /// Validated bounded user text.
        text: MessageText,
    },
    /// Append the assistant output for the active text execution.
    AppendAssistantMessage {
        /// Server-generated message identity.
        message_id: MessageId,
        /// Coordinating TaskRun.
        taskrun_id: TaskRunId,
        /// Exact active attempt.
        attempt_id: AttemptId,
        /// Validated bounded assistant text.
        text: MessageText,
    },
    /// Release the active generation without creating an assistant message.
    FailGeneration {
        /// Coordinating TaskRun.
        taskrun_id: TaskRunId,
        /// Exact active attempt.
        attempt_id: AttemptId,
        /// Closed, non-sensitive terminal reason.
        reason: GenerationFailureReason,
    },
    /// Release the exact active generation after an explicitly acknowledged
    /// successor was atomically created for an unknown external effect.
    SupersedeGenerationUnknown {
        /// Predecessor TaskRun owning the active generation.
        taskrun_id: TaskRunId,
        /// Exact active attempt.
        attempt_id: AttemptId,
        /// Newly created successor TaskRun.
        successor_taskrun_id: TaskRunId,
        /// Digest of the closed duplicate-execution-and-cost acknowledgement.
        acknowledgement_digest: IntegrityDigest,
    },
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

// ── SubmitTaskRun ──────────────────────────────────────────────────────────

/// Client-authorized command creating one TaskRun already bound to the
/// runtime-owned admission queue.
///
/// Unlike [`CreateTaskRun`], submitting commits `TaskRunCreated` and
/// `TaskRunQueued` as one atomic event batch; admission, attempt start, and
/// terminal completion stay runtime-owned.
#[derive(Debug, Clone)]
pub struct SubmitTaskRun {
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

    /// Fail a generation with a closed, non-sensitive terminal reason.
    FailGeneration {
        /// Closed reason shared with the coordinating Conversation event.
        reason: GenerationFailureReason,
    },

    /// Start a reconciliation pass.
    StartReconciliation,

    /// Complete a reconciliation pass — transitions back to running.
    CompleteReconciliation,

    /// Mark the task run as unrecoverable (terminal).
    MarkUnrecoverable,

    /// Mark an uncertain TaskRun as superseded by one explicit successor.
    UserSupersedeUnknown {
        /// Exact predecessor attempt whose outcome remains uncertain.
        predecessor_attempt_id: AttemptId,
        /// The successor TaskRun created in the same transaction.
        successor_taskrun_id: TaskRunId,
        /// Digest of the closed duplicate-execution-and-cost acknowledgement.
        acknowledgement_digest: IntegrityDigest,
    },

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
    include!("command/tests.rs");
}
