use super::*;

impl TaskRun {
    // ── decide_create ────────────────────────────────────────────────────

    /// Handle a [`CreateTaskRun`] command — produces the initial event.
    ///
    /// Assumes the aggregate does not exist yet.
    pub fn decide_create(
        command: CreateTaskRun,
    ) -> Result<DomainEventDraft<TaskRunEvent>, DomainError> {
        let aggregate_id = AggregateId::TaskRun(command.taskrun_id);
        Ok(DomainEventDraft::new(
            aggregate_id.clone(),
            aggregate_id,
            1,
            Sensitivity::Public,
            TaskRunEvent::TaskRunCreated,
        ))
    }

    /// Handles a [`SubmitTaskRun`](crate::command::SubmitTaskRun) command —
    /// produces the client-authorized entry batch.
    ///
    /// Assumes the aggregate does not exist yet. The only valid submit commit
    /// is this exact two-event batch: `TaskRunCreated` followed by
    /// `TaskRunQueued`. Admission, attempt start, and terminal completion stay
    /// runtime-owned and are never part of a client submit.
    pub fn decide_submit(
        command: SubmitTaskRun,
    ) -> Result<Vec<DomainEventDraft<TaskRunEvent>>, DomainError> {
        let aggregate_id = AggregateId::TaskRun(command.taskrun_id);
        let draft = |payload| {
            DomainEventDraft::new(
                aggregate_id.clone(),
                aggregate_id.clone(),
                1,
                Sensitivity::Public,
                payload,
            )
        };
        Ok(vec![
            draft(TaskRunEvent::TaskRunCreated),
            draft(TaskRunEvent::TaskRunQueued),
        ])
    }

    /// Creates and starts one TaskRun as a single valid event batch.
    ///
    /// This is used by coordinators that durably bind accepted work to an
    /// execution attempt in the same transaction. The resulting stream is
    /// equivalent to create → queue → admit → start-attempt.
    pub fn decide_create_running(
        command: CreateTaskRun,
        attempt_id: AttemptId,
    ) -> Result<Vec<DomainEventDraft<TaskRunEvent>>, DomainError> {
        let aggregate_id = AggregateId::TaskRun(command.taskrun_id);
        let draft = |payload| {
            DomainEventDraft::new(
                aggregate_id.clone(),
                aggregate_id.clone(),
                1,
                Sensitivity::Public,
                payload,
            )
        };
        Ok(vec![
            draft(TaskRunEvent::TaskRunCreated),
            draft(TaskRunEvent::TaskRunQueued),
            draft(TaskRunEvent::TaskRunAdmitted),
            draft(TaskRunEvent::AttemptStarted { attempt_id }),
        ])
    }
}

include!("commands/lifecycle.rs");
include!("commands/loop.rs");
include!("commands/recovery.rs");

impl TaskRun {
    /// Handle a command against an existing aggregate — produces zero or
    /// more events.
    pub fn decide(
        &self,
        command: TaskRunCommand,
    ) -> Result<Vec<DomainEventDraft<TaskRunEvent>>, DomainError> {
        if self.state.is_terminal() {
            return Err(DomainError::TerminalImmutable {
                current: self.state,
            });
        }

        match command {
            TaskRunCommand::Admit
            | TaskRunCommand::Queue
            | TaskRunCommand::StartAttempt { .. }
            | TaskRunCommand::WaitForApproval
            | TaskRunCommand::Resume
            | TaskRunCommand::StartRetry { .. }
            | TaskRunCommand::CompleteRetry { .. }
            | TaskRunCommand::StartCheckpoint
            | TaskRunCommand::CommitCheckpoint
            | TaskRunCommand::RequestCancellation
            | TaskRunCommand::CompleteCancellation
            | TaskRunCommand::Complete { .. }
            | TaskRunCommand::Fail { .. }
            | TaskRunCommand::FailGeneration { .. }
            | TaskRunCommand::StartReconciliation
            | TaskRunCommand::CompleteReconciliation
            | TaskRunCommand::MarkUnrecoverable => self.decide_lifecycle(command),
            TaskRunCommand::StartLoopCycle { .. }
            | TaskRunCommand::CommitContext { .. }
            | TaskRunCommand::CommitPlan { .. }
            | TaskRunCommand::RecordStepOutcome { .. }
            | TaskRunCommand::CompleteLoopCycle { .. }
            | TaskRunCommand::CreateNextCycle { .. }
            | TaskRunCommand::ResumeLoopWait { .. } => self.decide_loop(command),
            TaskRunCommand::ScheduleRetry { .. }
            | TaskRunCommand::ActivateScheduledRetryAttempt { .. }
            | TaskRunCommand::CommitRecoveryResume { .. }
            | TaskRunCommand::CommitLoopCheckpoint { .. } => self.decide_recovery(command),
        }
    }
}
