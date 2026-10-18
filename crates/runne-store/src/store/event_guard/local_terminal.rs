use super::{
    AggregateId, CommitError, StorageFailureKind, TaskRunEvent, UncommittedEvent, storage_failure,
};
use rusqlite::OptionalExtension;

pub(in crate::store) fn guard_local_command_terminal(
    transaction: &rusqlite::Transaction<'_>,
    event: &UncommittedEvent<TaskRunEvent>,
) -> Result<(), CommitError> {
    let id = match event.aggregate_id() {
        AggregateId::TaskRun(id) => *id,
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    };
    let route: Option<(i64, i64, i64)> = transaction
        .query_row(
            "SELECT route,provenance,cutover_version FROM taskrun_local_permission_routes
             WHERE taskrun_id=?1",
            [id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let terminal_event = matches!(
        event.payload(),
        TaskRunEvent::TaskRunCompleted { .. }
            | TaskRunEvent::TaskRunFailed { .. }
            | TaskRunEvent::CancellationCompleted
            | TaskRunEvent::TaskRunCancelled
            | TaskRunEvent::BudgetExhausted
            | TaskRunEvent::PolicyDenied
            | TaskRunEvent::Unrecoverable
    );
    match route {
        Some((1, 1, 68)) => {}
        Some((2, 3, 68)) if terminal_event => {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        Some((2, 3, 68)) => return Ok(()),
        Some((1, 2, 68)) if terminal_event => {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        Some((1, 2, 68)) => return Ok(()),
        Some(_) => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
        None => {}
    }
    let terminal_expectation = match event.payload() {
        TaskRunEvent::TaskRunCompleted {
            result: runne_domain::command::TerminalResult::Success,
        } => Some(("completed", Some(true))),
        TaskRunEvent::TaskRunCompleted {
            result: runne_domain::command::TerminalResult::Failure { .. },
        } => Some(("completed", Some(false))),
        TaskRunEvent::TaskRunFailed { reason } if reason == "dispatch_not_started" => {
            Some(("no_effect_terminal", None))
        }
        TaskRunEvent::TaskRunFailed { .. } => Some(("completed", Some(false))),
        _ => None,
    };
    let Some((expected_state, expected_success)) = terminal_expectation else {
        return Ok(());
    };
    let local: Option<(String, Option<i32>)> = transaction
        .query_row(
            "SELECT state,exit_code FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if let Some((state, exit)) = local {
        let valid = if expected_state == "no_effect_terminal" && state == "denied" {
            super::super::taskrun_no_effect_proof::authenticated_local_denial(transaction, id)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?
        } else {
            state == expected_state
                && expected_success
                    .is_none_or(|success| exit.is_some_and(|code| (code == 0) == success))
        };
        if !valid {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    }
    Ok(())
}
