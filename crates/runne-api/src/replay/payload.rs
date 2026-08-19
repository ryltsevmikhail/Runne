/// Closed, semantic replay payload published to local runtime clients.
///
/// This DTO intentionally excludes persistence codec bytes, database
/// positions, idempotency material, actor storage bytes, integrity digests,
/// and internal integrity-profile identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all_fields = "camelCase")]
pub enum CanonicalReplayPayloadV1 {
    /// A Conversation was created in one workspace.
    #[serde(rename = "conversation.created")]
    ConversationCreated {
        /// Owning workspace identity.
        workspace_id: String,
    },
    /// A bounded user or assistant message was appended.
    #[serde(rename = "conversation.message.appended")]
    ConversationMessageAppended {
        /// Closed message role.
        role: CanonicalMessageRoleV1,
        /// Message identity.
        message_id: String,
        /// Coordinating task-run identity.
        task_run_id: String,
        /// Exact attempt identity.
        attempt_id: String,
        /// Validated bounded text.
        text: String,
    },
    /// A Conversation generation terminated without an assistant message.
    #[serde(rename = "conversation.generation.failed")]
    ConversationGenerationFailed {
        /// Coordinating task-run identity.
        task_run_id: String,
        /// Exact attempt identity.
        attempt_id: String,
        /// Closed, non-sensitive terminal reason.
        reason: String,
    },
    /// A Conversation was closed.
    #[serde(rename = "conversation.closed")]
    ConversationClosed,
    /// A TaskRun was created.
    #[serde(rename = "taskRun.created")]
    TaskRunCreated,
    /// A TaskRun was queued.
    #[serde(rename = "taskRun.queued")]
    TaskRunQueued,
    /// A TaskRun was admitted.
    #[serde(rename = "taskRun.admitted")]
    TaskRunAdmitted,
    /// A TaskRun attempt started.
    #[serde(rename = "taskRun.attempt.started")]
    TaskRunAttemptStarted {
        /// Attempt identity.
        attempt_id: String,
    },
    /// A TaskRun entered a waiting state.
    #[serde(rename = "taskRun.wait.started")]
    TaskRunWaitStarted,
    /// A TaskRun resumed.
    #[serde(rename = "taskRun.resumed")]
    TaskRunResumed,
    /// A TaskRun retry started.
    #[serde(rename = "taskRun.retry.started")]
    TaskRunRetryStarted {
        /// Retry attempt identity.
        attempt_id: String,
    },
    /// A TaskRun retry completed.
    #[serde(rename = "taskRun.retry.completed")]
    TaskRunRetryCompleted {
        /// Retry attempt identity.
        attempt_id: String,
    },
    /// A TaskRun checkpoint started.
    #[serde(rename = "taskRun.checkpoint.started")]
    TaskRunCheckpointStarted,
    /// A TaskRun checkpoint committed.
    #[serde(rename = "taskRun.checkpoint.committed")]
    TaskRunCheckpointCommitted,
    /// TaskRun cancellation was requested.
    #[serde(rename = "taskRun.cancellation.requested")]
    TaskRunCancellationRequested,
    /// TaskRun cancellation completed.
    #[serde(rename = "taskRun.cancellation.completed")]
    TaskRunCancellationCompleted,
    /// A TaskRun completed with a closed outcome.
    #[serde(rename = "taskRun.completed")]
    TaskRunCompleted {
        /// `success` or `failure`.
        outcome: String,
        /// Redacted failure reason, present only for failure.
        reason: Option<String>,
    },
    /// A TaskRun failed.
    #[serde(rename = "taskRun.failed")]
    TaskRunFailed {
        /// Redacted terminal reason.
        reason: String,
    },
    /// A TaskRun exhausted its budget.
    #[serde(rename = "taskRun.budget.exhausted")]
    TaskRunBudgetExhausted,
    /// Policy denied TaskRun execution.
    #[serde(rename = "taskRun.policy.denied")]
    TaskRunPolicyDenied,
    /// TaskRun reconciliation started.
    #[serde(rename = "taskRun.reconciliation.started")]
    TaskRunReconciliationStarted,
    /// TaskRun reconciliation completed.
    #[serde(rename = "taskRun.reconciliation.completed")]
    TaskRunReconciliationCompleted,
    /// A TaskRun became unrecoverable.
    #[serde(rename = "taskRun.unrecoverable")]
    TaskRunUnrecoverable,
    /// A TaskRun was cancelled directly.
    #[serde(rename = "taskRun.cancelled")]
    TaskRunCancelled,
    /// One TaskRun loop cycle started.
    #[serde(rename = "taskRun.loop.cycle.started")]
    TaskRunLoopCycleStarted {
        /// Cycle identity.
        cycle_id: String,
        /// Attempt identity.
        attempt_id: String,
        /// Aggregate-owned cycle sequence.
        sequence: u64,
        /// Optional parent cycle.
        parent_cycle_id: Option<String>,
    },
    /// One immutable context manifest was committed.
    #[serde(rename = "taskRun.context.committed")]
    TaskRunContextCommitted {
        /// Cycle identity.
        cycle_id: String,
        /// Manifest identity.
        manifest_id: String,
        /// Immutable manifest revision.
        revision: u64,
    },
    /// One immutable plan revision was committed.
    #[serde(rename = "taskRun.plan.committed")]
    TaskRunPlanCommitted {
        /// Cycle identity.
        cycle_id: String,
        /// Plan identity.
        plan_id: String,
        /// Immutable plan revision.
        revision: u64,
        /// Closed ordered proposal indexes.
        expected_proposal_indexes: Vec<u32>,
    },
    /// One proposal outcome was recorded.
    #[serde(rename = "taskRun.step.outcome.recorded")]
    TaskRunStepOutcomeRecorded {
        /// Cycle identity.
        cycle_id: String,
        /// Proposal index.
        proposal_index: u32,
        /// Step identity.
        step_id: String,
        /// Closed outcome spelling.
        outcome: String,
    },
    /// One loop cycle completed.
    #[serde(rename = "taskRun.loop.cycle.completed")]
    TaskRunLoopCycleCompleted {
        /// Cycle identity.
        cycle_id: String,
        /// Attempt identity.
        attempt_id: String,
        /// Closed disposition spelling.
        disposition: String,
    },
    /// One successor cycle was reserved.
    #[serde(rename = "taskRun.next.cycle.created")]
    TaskRunNextCycleCreated {
        /// Parent cycle identity.
        parent_cycle_id: String,
        /// Successor cycle identity.
        successor_cycle_id: String,
        /// Attempt identity.
        attempt_id: String,
        /// Aggregate-owned cycle sequence.
        sequence: u64,
    },
    /// One retry was durably scheduled.
    #[serde(rename = "taskRun.retry.scheduled")]
    TaskRunRetryScheduled {
        /// Retry ordinal.
        ordinal: u64,
        /// Superseded attempt identity.
        old_attempt_id: String,
        /// Reserved retry attempt identity.
        new_attempt_id: String,
        /// Abandoned cycle identity.
        abandoned_cycle_id: String,
        /// Bounded retry delay.
        delay_millis: u64,
        /// Scheduled activation time.
        due_at_unix_micros: i64,
    },
    /// A scheduled retry attempt was activated.
    #[serde(rename = "taskRun.retry.attempt.activated")]
    TaskRunRetryAttemptActivated {
        /// Retry ordinal.
        ordinal: u64,
        /// Activated attempt identity.
        attempt_id: String,
        /// Activation time.
        activated_at_unix_micros: i64,
    },
    /// Recovery reconciliation resumed execution.
    #[serde(rename = "taskRun.recovery.resume.started")]
    TaskRunRecoveryResumeStarted {
        /// New attempt identity.
        new_attempt_id: String,
        /// Monotonic recovery generation.
        new_generation: u64,
        /// Optional abandoned cycle.
        abandoned_cycle_id: Option<String>,
    },
    /// A loop checkpoint batch started.
    #[serde(rename = "taskRun.loop.checkpoint.started")]
    TaskRunLoopCheckpointStarted {
        /// Checkpoint identity.
        checkpoint_id: String,
    },
    /// A loop checkpoint body was recorded.
    #[serde(rename = "taskRun.loop.checkpoint.recorded")]
    TaskRunLoopCheckpointRecorded {
        /// Checkpoint identity.
        checkpoint_id: String,
    },
    /// A loop checkpoint batch committed.
    #[serde(rename = "taskRun.loop.checkpoint.committed")]
    TaskRunLoopCheckpointCommitted {
        /// Checkpoint identity.
        checkpoint_id: String,
    },
    /// Exact wake evidence was accepted.
    #[serde(rename = "taskRun.loop.wake.accepted")]
    TaskRunLoopWakeAccepted {
        /// Cycle identity.
        cycle_id: String,
        /// Wake-evidence identity.
        evidence_id: String,
        /// Closed authority source.
        source: String,
    },
}
