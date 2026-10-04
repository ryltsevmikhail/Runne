use crate::codec::{StoreCodec, TaskRunEventCodec};

pub(crate) fn local_terminal_proof_matches(
    connection: &Connection,
    taskrun_id: &[u8],
    attempt_id: &[u8],
    node_id: &[u8],
    node_epoch: i64,
    fence: i64,
    event: &runne_domain::task_run::TaskRunEvent,
) -> SqliteResult<bool> {
    struct LocalTerminalBinding {
        attempt_id: Vec<u8>,
        node_id: Vec<u8>,
        node_epoch: i64,
        fence: i64,
        conversation_id: Vec<u8>,
        workspace_id: Vec<u8>,
        command_digest: Vec<u8>,
        area_identity: Vec<u8>,
        state: String,
        exit_code: Option<i64>,
    }
    let local = connection
        .query_row(
            "SELECT attempt_id,node_id,node_epoch,fence,conversation_id,workspace_id,
                    command_digest,managed_area_identity,state,exit_code
             FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [taskrun_id],
            |row| {
                Ok(LocalTerminalBinding {
                    attempt_id: row.get(0)?,
                    node_id: row.get(1)?,
                    node_epoch: row.get(2)?,
                    fence: row.get(3)?,
                    conversation_id: row.get(4)?,
                    workspace_id: row.get(5)?,
                    command_digest: row.get(6)?,
                    area_identity: row.get(7)?,
                    state: row.get(8)?,
                    exit_code: row.get(9)?,
                })
            },
        )
        .optional()?;
    let Some(local) = local else {
        return Ok(false);
    };
    if local.attempt_id != attempt_id
        || local.node_id != node_id
        || local.node_epoch != node_epoch
        || local.fence != fence
        || !matches!(local.state.as_str(), "completed" | "cancelled")
        || !local_area_identity_matches(&local.area_identity, taskrun_id, attempt_id)
    {
        return Ok(false);
    }
    let Ok(taskrun_bytes) = <[u8; 16]>::try_from(taskrun_id) else {
        return Ok(false);
    };
    let Ok(Some(origin)) =
        crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
            connection,
            runne_domain::id::TaskRunId::from_bytes(taskrun_bytes),
        )
    else {
        return Ok(false);
    };
    if local.conversation_id.as_slice() != origin.conversation_id.as_bytes()
        || local.workspace_id.as_slice() != origin.workspace_id.as_bytes()
        || origin
            .input
            .local_command()
            .is_none_or(|command| command.intent_digest().as_slice() != local.command_digest)
    {
        return Ok(false);
    }
    let claim: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT new_version,started_event_id FROM taskrun_claim_receipts
             WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5",
            rusqlite::params![taskrun_id, fence, attempt_id, node_id, node_epoch],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((claim_version, started_event_id)) = claim else {
        return Ok(false);
    };
    if claim_version != 4 {
        return Ok(false);
    }
    let started: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT event_id,payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=4",
            [taskrun_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((event_id, payload)) = started else {
        return Ok(false);
    };
    if event_id != started_event_id
        || !matches!(
            TaskRunEventCodec.decode(&payload),
            Ok(runne_domain::task_run::TaskRunEvent::AttemptStarted { attempt_id: event_attempt })
                if event_attempt.as_bytes() == attempt_id
        )
    {
        return Ok(false);
    }
    Ok(local_attempt_terminal_state_matches(
        &local.state,
        local.exit_code,
        event,
    ))
}

fn local_cancellation_matches(
    connection: &Connection,
    taskrun_id: &[u8],
    attempt_id: &[u8],
    node_id: &[u8],
    node_epoch: i64,
    fence: i64,
    event: &runne_domain::task_run::TaskRunEvent,
) -> SqliteResult<bool> {
    if !submitted_local_command_origin(connection, taskrun_id)? {
        return Ok(true);
    }
    let Ok(taskrun_bytes) = <[u8; 16]>::try_from(taskrun_id) else {
        return Ok(false);
    };
    let origin = match crate::store::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
        connection,
        runne_domain::id::TaskRunId::from_bytes(taskrun_bytes),
    ) {
        Ok(Some(origin)) => origin,
        Ok(None) => return Ok(false),
        Err(_) => return Ok(false),
    };
    if origin.input.local_command().is_none() {
        return Ok(false);
    }
    local_terminal_proof_matches(
        connection, taskrun_id, attempt_id, node_id, node_epoch, fence, event,
    )
}

fn local_attempt_terminal_state_matches(
    state: &str,
    exit_code: Option<i64>,
    event: &runne_domain::task_run::TaskRunEvent,
) -> bool {
    match (state, exit_code, event) {
        (
            "completed",
            Some(0),
            runne_domain::task_run::TaskRunEvent::TaskRunCompleted {
                result: runne_domain::command::TerminalResult::Success,
            },
        ) => true,
        (
            "completed",
            Some(code @ 1..=255),
            runne_domain::task_run::TaskRunEvent::TaskRunCompleted {
                result: runne_domain::command::TerminalResult::Failure { reason },
            },
        ) => reason == &format!("local_command_exit_{code}"),
        (
            "cancelled",
            None,
            runne_domain::task_run::TaskRunEvent::TaskRunCancelled
            | runne_domain::task_run::TaskRunEvent::CancellationCompleted,
        ) => true,
        (
            "completed",
            Some(0..=255),
            runne_domain::task_run::TaskRunEvent::TaskRunCancelled
            | runne_domain::task_run::TaskRunEvent::CancellationCompleted,
        ) => true,
        _ => false,
    }
}

fn local_area_identity_matches(area: &[u8], taskrun_id: &[u8], attempt_id: &[u8]) -> bool {
    area.len() == 100
        && &area[..4] == b"RMA1"
        && area[4..20] != [0; 16]
        && area[28..36] != [0; 8]
        && area[44..52] != [0; 8]
        && area[52..68] == taskrun_id[..]
        && area[68..84] == attempt_id[..]
        && area[84..100] != [0; 16]
}
