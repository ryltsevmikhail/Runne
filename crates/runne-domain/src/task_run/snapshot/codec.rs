use super::{TaskRun, TaskRunSnapshotError, cycles, io, validation};
use crate::command::TerminalResult;
use crate::id::{AttemptId, TaskRunId};
use crate::task_run::TaskRunState;
use io::{In, MAX_BYTES, Out};

const VERSION: u8 = 2;

pub(super) fn encode(value: &TaskRun) -> Result<Vec<u8>, TaskRunSnapshotError> {
    validation::validate(value)?;
    let version = if value.input.is_some() { VERSION } else { 1 };
    let mut out = Out::new();
    out.u8(version);
    out.id(value.id.as_bytes());
    put_state(&mut out, value.state);
    put_opt_attempt(&mut out, value.active_attempt);
    out.len(value.attempt_history.len())?;
    for attempt in &value.attempt_history {
        out.id(attempt.as_bytes());
    }
    put_terminal(&mut out, value.terminal_result.as_ref())?;
    put_opt(&mut out, value.active_cycle.as_ref(), cycles::put_active)?;
    put_opt(
        &mut out,
        value.last_completed_cycle.as_ref(),
        cycles::put_completed,
    )?;
    put_opt(&mut out, value.pending_successor.as_ref(), |out, value| {
        cycles::put_successor(out, value);
        Ok(())
    })?;
    put_opt(&mut out, value.pending_loop_wait.as_ref(), cycles::put_wait)?;
    put_opt(&mut out, value.pending_retry.as_ref(), |out, value| {
        cycles::put_retry(out, value);
        Ok(())
    })?;
    put_opt(
        &mut out,
        value.pending_loop_checkpoint.as_ref(),
        |out, value| {
            cycles::put_checkpoint(out, value);
            Ok(())
        },
    )?;
    out.len(value.cycle_history.len())?;
    for entry in &value.cycle_history {
        cycles::put_history(&mut out, entry);
    }
    out.u64(value.recovery_generation);
    if version == VERSION {
        match (&value.conversation_id, &value.workspace_id, &value.input) {
            (Some(conversation), Some(workspace), Some(input)) => {
                out.u8(1);
                out.id(conversation.as_bytes());
                out.id(workspace.as_bytes());
                out.string(input.prompt())?;
            }
            _ => return Err(TaskRunSnapshotError::InvalidState),
        }
    }
    out.finish()
}

pub(super) fn decode(bytes: &[u8]) -> Result<TaskRun, TaskRunSnapshotError> {
    if bytes.len() > MAX_BYTES {
        return Err(TaskRunSnapshotError::InvalidEncoding);
    }
    let mut input = In::new(bytes)?;
    let version = input.u8()?;
    if version != 1 && version != VERSION {
        return Err(TaskRunSnapshotError::InvalidEncoding);
    }
    let id = TaskRunId::from_bytes(input.id()?);
    let state = get_state(&mut input)?;
    let active_attempt = get_opt_attempt(&mut input)?;
    let attempts = input.len()?;
    let mut attempt_history = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        attempt_history.push(AttemptId::from_bytes(input.id()?));
    }
    let terminal_result = get_terminal(&mut input)?;
    let active_cycle = get_opt(&mut input, cycles::get_active)?;
    let last_completed_cycle = get_opt(&mut input, cycles::get_completed)?;
    let pending_successor = get_opt(&mut input, cycles::get_successor)?;
    let pending_loop_wait = get_opt(&mut input, cycles::get_wait)?;
    let pending_retry = get_opt(&mut input, cycles::get_retry)?;
    let pending_loop_checkpoint = get_opt(&mut input, cycles::get_checkpoint)?;
    let count = input.len()?;
    let mut cycle_history = Vec::with_capacity(count);
    for _ in 0..count {
        cycle_history.push(cycles::get_history(&mut input)?);
    }
    let recovery_generation = input.u64()?;
    let (conversation_id, workspace_id, task_input) = if version == 1 {
        (None, None, None)
    } else {
        match input.u8()? {
            0 => (None, None, None),
            1 => {
                let conversation_id = crate::id::ConversationId::from_bytes(input.id()?);
                let workspace_id = crate::id::WorkspaceId::from_bytes(input.id()?);
                let prompt = input.string()?;
                let task_input = super::super::TaskRunInput::new(prompt)
                    .map_err(|_| TaskRunSnapshotError::InvalidState)?;
                (Some(conversation_id), Some(workspace_id), Some(task_input))
            }
            _ => return Err(TaskRunSnapshotError::InvalidEncoding),
        }
    };
    if !input.done() {
        return Err(TaskRunSnapshotError::InvalidEncoding);
    }
    let value = TaskRun {
        id,
        conversation_id,
        workspace_id,
        input: task_input,
        state,
        active_attempt,
        attempt_history,
        terminal_result,
        active_cycle,
        last_completed_cycle,
        pending_successor,
        pending_loop_wait,
        pending_retry,
        pending_loop_checkpoint,
        cycle_history,
        recovery_generation,
    };
    validation::validate(&value)?;
    Ok(value)
}

fn put_state(out: &mut Out, value: TaskRunState) {
    out.u8(match value {
        TaskRunState::Created => 1,
        TaskRunState::Queued => 2,
        TaskRunState::Admitted => 3,
        TaskRunState::Running => 4,
        TaskRunState::Waiting => 5,
        TaskRunState::Retrying => 6,
        TaskRunState::Checkpointing => 7,
        TaskRunState::Cancelling => 8,
        TaskRunState::Reconciling => 9,
        TaskRunState::Succeeded => 10,
        TaskRunState::Failed => 11,
        TaskRunState::Cancelled => 12,
        TaskRunState::BudgetExhausted => 13,
        TaskRunState::PolicyDenied => 14,
        TaskRunState::Unrecoverable => 15,
    });
}
fn get_state(input: &mut In<'_>) -> Result<TaskRunState, TaskRunSnapshotError> {
    match input.u8()? {
        1 => Ok(TaskRunState::Created),
        2 => Ok(TaskRunState::Queued),
        3 => Ok(TaskRunState::Admitted),
        4 => Ok(TaskRunState::Running),
        5 => Ok(TaskRunState::Waiting),
        6 => Ok(TaskRunState::Retrying),
        7 => Ok(TaskRunState::Checkpointing),
        8 => Ok(TaskRunState::Cancelling),
        9 => Ok(TaskRunState::Reconciling),
        10 => Ok(TaskRunState::Succeeded),
        11 => Ok(TaskRunState::Failed),
        12 => Ok(TaskRunState::Cancelled),
        13 => Ok(TaskRunState::BudgetExhausted),
        14 => Ok(TaskRunState::PolicyDenied),
        15 => Ok(TaskRunState::Unrecoverable),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}
fn put_opt_attempt(out: &mut Out, value: Option<AttemptId>) {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            out.id(value.as_bytes());
        }
    }
}
fn get_opt_attempt(input: &mut In<'_>) -> Result<Option<AttemptId>, TaskRunSnapshotError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(AttemptId::from_bytes(input.id()?))),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}
fn put_terminal(out: &mut Out, value: Option<&TerminalResult>) -> Result<(), TaskRunSnapshotError> {
    match value {
        None => out.u8(0),
        Some(TerminalResult::Success) => out.u8(1),
        Some(TerminalResult::Failure { reason }) => {
            out.u8(2);
            out.string(reason)?;
        }
    }
    Ok(())
}
fn get_terminal(input: &mut In<'_>) -> Result<Option<TerminalResult>, TaskRunSnapshotError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(TerminalResult::Success)),
        2 => Ok(Some(TerminalResult::Failure {
            reason: input.string()?,
        })),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}
fn put_opt<T>(
    out: &mut Out,
    value: Option<&T>,
    put: impl FnOnce(&mut Out, &T) -> Result<(), TaskRunSnapshotError>,
) -> Result<(), TaskRunSnapshotError> {
    match value {
        None => out.u8(0),
        Some(value) => {
            out.u8(1);
            put(out, value)?;
        }
    }
    Ok(())
}
fn get_opt<T>(
    input: &mut In<'_>,
    get: impl FnOnce(&mut In<'_>) -> Result<T, TaskRunSnapshotError>,
) -> Result<Option<T>, TaskRunSnapshotError> {
    match input.u8()? {
        0 => Ok(None),
        1 => Ok(Some(get(input)?)),
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}
