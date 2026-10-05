use super::super::*;
use runne_application::ports::TextGenerationPhase;
use runne_domain::task_run::{TaskRun, TaskRunState};
use rusqlite::Connection;

#[path = "d2_tool_loop/conversation.rs"]
mod conversation;
#[path = "d2_tool_loop/evidence.rs"]
mod evidence;
#[path = "d2_tool_loop/invocations.rs"]
mod invocations;
#[path = "d2_tool_loop/proof.rs"]
mod proof;
#[path = "d2_tool_loop/recognition.rs"]
mod recognition;

pub(super) fn validate(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> Result<bool, CommitError> {
    if receipt.phase != TextGenerationPhase::Rejected {
        return Ok(false);
    }
    let budget_table_installed: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table'
             AND name='taskrun_tool_budgets')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| invalid())?;
    if !budget_table_installed {
        return Ok(false);
    }
    let taskrun = super::super::taskrun_claim::stream_validate::verify_stream(
        connection,
        receipt.taskrun_id,
        Some(receipt.taskrun_version),
    )
    .map_err(|_| invalid())?;
    let aggregate = TaskRun::replay(&taskrun.events).map_err(|_| invalid())?;
    let has_d2_cycle = taskrun.events.iter().any(|event| {
        matches!(
            event.payload(),
            TaskRunEvent::LoopCycleStarted { attempt_id, .. }
                if *attempt_id == receipt.attempt_id
        )
    });
    let is_d2 = aggregate
        .snapshot_v1()
        .input()
        .and_then(|input| input.selected_profile())
        .is_some_and(|profile| profile.profile_id() == "runne-linux-agent-tools-v1");
    if !recognition::is_d2_cancellation(connection, receipt.taskrun_id, is_d2, has_d2_cycle)? {
        return Ok(false);
    }
    if aggregate.state() != TaskRunState::Cancelled
        || taskrun
            .events
            .last()
            .is_none_or(|event| event.payload() != &TaskRunEvent::CancellationCompleted)
        || !taskrun
            .events
            .iter()
            .any(|event| event.payload() == &TaskRunEvent::CancellationRequested)
    {
        return Err(invalid());
    }
    let terminal_event_id = taskrun
        .events
        .last()
        .map(|event| *event.event_id().as_bytes())
        .ok_or_else(invalid)?;
    proof::verify(connection, receipt, &terminal_event_id)?;
    conversation::verify_conversation(connection, receipt)?;
    Ok(true)
}

pub(super) fn validate_evidence(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    evidence: runne_application::ports::D2ToolLoopCancellationEvidence,
) -> Result<(), CommitError> {
    evidence::validate(connection, receipt, evidence)
}

fn invalid() -> CommitError {
    super::super::parse_helpers::storage_failure(StorageFailureKind::IntegrityViolation)
}
