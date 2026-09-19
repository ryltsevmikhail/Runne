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
    /// A task run was submitted: created and queued by one atomic commit.
    TaskRunSubmitted {
        /// The task run ID.
        taskrun_id: TaskRunId,
        /// The committed stream version after `Created + Queued` (always 2).
        new_version: u64,
    },
    /// Cancellation was durably requested for a task run.
    TaskRunCancellationRequested {
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
