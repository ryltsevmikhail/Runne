fn into_application_context(
    context: TaskRunCommandContext,
) -> Result<ApplicationCommandContext, TaskRunHostError> {
    let actor = Actor::new(context.actor.as_str().to_owned())
        .map_err(|_| TaskRunHostError::InvariantViolation)?;
    Ok(ApplicationCommandContext {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key,
        principal_id: PrincipalId(context.principal.as_str().to_owned()),
        actor,
    })
}

fn terminal_result_to_domain(result: CanonicalTerminalResult) -> TerminalResult {
    match result {
        CanonicalTerminalResult::Success => TerminalResult::Success,
        CanonicalTerminalResult::Failure { reason } => TerminalResult::Failure { reason },
    }
}

fn terminal_result_to_canonical(result: TerminalResult) -> CanonicalTerminalResult {
    match result {
        TerminalResult::Success => CanonicalTerminalResult::Success,
        TerminalResult::Failure { reason } => CanonicalTerminalResult::Failure { reason },
    }
}

fn state_to_canonical(state: TaskRunState) -> CanonicalTaskRunState {
    match state {
        TaskRunState::Created => CanonicalTaskRunState::Created,
        TaskRunState::Queued => CanonicalTaskRunState::Queued,
        TaskRunState::Admitted => CanonicalTaskRunState::Admitted,
        TaskRunState::Running => CanonicalTaskRunState::Running,
        TaskRunState::Waiting => CanonicalTaskRunState::Waiting,
        TaskRunState::Retrying => CanonicalTaskRunState::Retrying,
        TaskRunState::Checkpointing => CanonicalTaskRunState::Checkpointing,
        TaskRunState::Cancelling => CanonicalTaskRunState::Cancelling,
        TaskRunState::Reconciling => CanonicalTaskRunState::Reconciling,
        TaskRunState::Succeeded => CanonicalTaskRunState::Succeeded,
        TaskRunState::Failed => CanonicalTaskRunState::Failed,
        TaskRunState::Cancelled => CanonicalTaskRunState::Cancelled,
        TaskRunState::BudgetExhausted => CanonicalTaskRunState::BudgetExhausted,
        TaskRunState::PolicyDenied => CanonicalTaskRunState::PolicyDenied,
        TaskRunState::Unrecoverable => CanonicalTaskRunState::Unrecoverable,
    }
}

fn map_runtime_error(error: RuntimeError) -> TaskRunHostError {
    match error {
        RuntimeError::Backpressure { .. } => TaskRunHostError::Backpressure,
        RuntimeError::RuntimeClosed | RuntimeError::WorkerExecutionFailed { .. } => {
            TaskRunHostError::Unavailable
        }
        RuntimeError::Application(error) => map_application_error(error),
        RuntimeError::ConversationApplication(_) => TaskRunHostError::InvariantViolation,
    }
}

fn map_application_error(error: ApplicationError) -> TaskRunHostError {
    match error {
        ApplicationError::AggregateNotFound { .. }
        | ApplicationError::EventStoreFailed(EventStoreError::NotFound) => {
            TaskRunHostError::NotFound
        }
        ApplicationError::VersionConflict { .. }
        | ApplicationError::IdempotencyConflict { .. }
        | ApplicationError::InvalidCommandFingerprint(_)
        | ApplicationError::Domain(DomainError::InvalidTransition { .. })
        | ApplicationError::Domain(DomainError::TerminalImmutable { .. }) => {
            TaskRunHostError::Conflict
        }
        ApplicationError::EventStoreFailed(_)
        | ApplicationError::StorageFailed(_)
        | ApplicationError::IdGenerationFailed(_)
        | ApplicationError::TimePortFailed(_)
        | ApplicationError::RetryScheduleRejected(_)
        | ApplicationError::WakeEvidenceRejected(_)
        | ApplicationError::ReconciliationRejected(_)
        | ApplicationError::VerificationRejected(_) => TaskRunHostError::Unavailable,
        ApplicationError::VersionExhausted { .. }
        | ApplicationError::Domain(_)
        | ApplicationError::StreamConsistencyViolation(_)
        | ApplicationError::CommitVersionMismatch { .. }
        | ApplicationError::InvalidAuthorityResult => TaskRunHostError::InvariantViolation,
    }
}

fn map_event_store_error(error: EventStoreError) -> TaskRunHostError {
    match error {
        EventStoreError::NotFound => TaskRunHostError::NotFound,
        EventStoreError::CorruptData | EventStoreError::Unavailable => {
            TaskRunHostError::Unavailable
        }
    }
}
