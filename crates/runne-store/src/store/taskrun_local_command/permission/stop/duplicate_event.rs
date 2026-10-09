use runne_application::{
    commands::CommandOutcome,
    ports::{CommandCommit, CommitError},
};
use runne_domain::{
    command::TerminalResult,
    task_run::{TaskRunEvent, TaskRunState},
};
use runne_platform::local_command_linux::LinuxLeaderExitKindV1;
use rusqlite::Transaction;

pub(crate) fn verify_duplicate_event(
    tx: &Transaction<'_>,
    terminal: &super::super::terminal::PermissionTerminalCommitV1<'_, '_>,
    payload: &CommandCommit,
    stored_result: &CommandOutcome,
    facts: &super::super::terminal::PermissionTerminalDuplicateFacts,
) -> Result<(), CommitError> {
    let invalid = super::super::terminal::terminal_integrity_error;
    let event = payload.events.first().ok_or_else(invalid)?;
    let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
        tx,
        terminal.identity.taskrun_id,
        None,
    )
    .map_err(|_| invalid())?;
    let saved = stream.events.last().ok_or_else(invalid)?;
    let version = facts.terminal_version;
    let completed = matches!(stored_result, CommandOutcome::TaskRunCompleted { taskrun_id, new_version }
        if *taskrun_id == terminal.identity.taskrun_id && *new_version == version);
    let cancelled = matches!(stored_result, CommandOutcome::TaskRunCancellationCompleted { taskrun_id, new_version }
        if *taskrun_id == terminal.identity.taskrun_id && *new_version == version);
    let stopped = super::super::stop::stop_reason(
        tx,
        terminal.identity.taskrun_id.as_bytes(),
        terminal.identity.attempt_id.as_bytes(),
        &facts.binding_digest,
    )
    .map_err(|_| invalid())?
    .is_some();
    super::super::stop::validate_duplicate_terminal(
        tx,
        terminal.identity.taskrun_id.as_bytes(),
        terminal.identity.attempt_id.as_bytes(),
        &facts.binding_digest,
        event.payload(),
    )
    .map_err(|_| invalid())?;
    let matches = match (stream.state, event.payload(), facts.exit_kind) {
        (
            TaskRunState::Succeeded,
            TaskRunEvent::TaskRunCompleted {
                result: TerminalResult::Success,
            },
            LinuxLeaderExitKindV1::Exited { code: 0 },
        ) => completed && !stopped,
        (
            TaskRunState::Succeeded,
            TaskRunEvent::TaskRunCompleted {
                result: TerminalResult::Failure { reason },
            },
            LinuxLeaderExitKindV1::Exited { code: 1..=255 },
        ) => {
            reason == &format!("local_command_exit_{}", facts.legacy_exit_code)
                && completed
                && !stopped
        }
        (TaskRunState::Failed, TaskRunEvent::TaskRunFailed { reason }, _)
            if reason == "local_command_policy_stopped_v1" =>
        {
            completed && stopped
        }
        (
            TaskRunState::Failed,
            TaskRunEvent::TaskRunFailed { reason },
            LinuxLeaderExitKindV1::Signaled { signal, .. },
        ) => reason == &format!("local_command_signal_v1_{signal}") && completed && !stopped,
        (TaskRunState::Cancelled, TaskRunEvent::CancellationCompleted, _) => cancelled && stopped,
        _ => false,
    };
    if payload.events.len() != 1
        || stored_result != &payload.command_result
        || stream.version != version
        || !matches
        || saved.event_id() != event.event_id()
        || saved.command_id() != &payload.command_id
        || saved.correlation_id() != event.correlation_id()
        || saved.idempotency_key() != &payload.idempotency_key
        || saved.actor() != event.actor()
        || saved.causation_id() != event.causation_id()
        || saved.sensitivity() != event.sensitivity()
        || saved.schema_version() != event.schema_version()
        || saved.payload() != event.payload()
        || event.command_id() != &payload.command_id
        || event.correlation_id()
            != &runne_domain::id::AggregateId::TaskRun(terminal.identity.taskrun_id)
    {
        return Err(invalid());
    }
    crate::store::taskrun_local_command::settlement::settle(
        tx,
        terminal.identity,
        &facts.area_identity,
        *event.event_id(),
        version,
    )
    .map_err(|_| invalid())
}
