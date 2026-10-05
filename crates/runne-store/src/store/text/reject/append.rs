use super::*;

pub(super) fn terminal_taskrun_head(
    stored_version: u64,
    d2_restart: Option<&D2ToolLoopRestartEvidence>,
) -> u64 {
    super::super::d2_tool_loop_restart::terminal_taskrun_head(stored_version, d2_restart)
}

pub(super) fn append_events_and_retire(
    tx: &rusqlite::Transaction<'_>,
    prohibited: &dyn runne_application::prohibited_content::ProhibitedContentPort,
    payload: &RejectTextGenerationCommit,
    d2_restart: Option<&D2ToolLoopRestartEvidence>,
    conversation_position: i64,
    taskrun_position: i64,
    now: i64,
) -> Result<(), CommitError> {
    diagnostics::on_error(
        "reject.append_conversation",
        append_conversation_event(
            tx,
            prohibited,
            &payload.conversation_events[0],
            payload.receipt.conversation_version,
            conversation_position,
            now,
        ),
    )?;
    diagnostics::on_error(
        "reject.append_taskrun",
        append_taskrun_event(
            tx,
            prohibited,
            &payload.taskrun_events[0],
            payload.receipt.taskrun_version,
            taskrun_position,
            now,
        ),
    )?;
    diagnostics::on_error(
        "reject.occupation_retire",
        if let Some(evidence) = d2_restart {
            super::super::d2_tool_loop_restart::retire_occupation(
                tx,
                evidence,
                &payload.taskrun_events[0],
                payload.receipt.taskrun_version,
            )
        } else {
            super::super::terminal_occupation::retire_terminal_occupation(
                tx,
                &payload.receipt,
                &payload.taskrun_events[0],
            )
        },
    )?;
    Ok(())
}
