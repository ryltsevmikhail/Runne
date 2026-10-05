use super::super::*;
use runne_application::ports::D2ToolLoopFailureV1;
use runne_domain::id::EventId;

pub(super) fn retire_occupation(
    tx: &rusqlite::Transaction<'_>,
    input: &D2ToolLoopFailureV1,
    event: EventId,
    version: u64,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let node = uuid::Uuid::parse_str(&input.assignment.node_id.0)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let parameters = params![
        input.taskrun_id.as_bytes(),
        input.assignment.fence.0 as i64,
        input.attempt_id.as_bytes(),
        node.as_bytes(),
        input.assignment.node_epoch as i64
    ];
    let state: Option<(String, Option<Vec<u8>>, String)> = tx.query_row(
        "SELECT state,release_event_id,dispatch_intent FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5",
        parameters,
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let saved_intent: Option<String> = tx
        .query_row(
            "SELECT state FROM taskrun_dispatch_intents
             WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5",
            params![
                input.taskrun_id.as_bytes(),
                input.assignment.fence.0 as i64,
                input.attempt_id.as_bytes(),
                node.as_bytes(),
                input.assignment.node_epoch as i64
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let expected_intent = saved_intent.as_deref().unwrap_or("absent");
    if !matches!(expected_intent, "absent" | "present" | "unknown") {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if state.as_ref().is_some_and(|(state, released, intent)| {
        state == "released"
            && intent == expected_intent
            && released.as_deref() == Some(event.as_bytes())
    }) {
        return verify_settlement(tx, input, event, version, node.as_bytes());
    }
    if !state.is_some_and(|(state, release, intent)| {
        state == "active" && release.is_none() && intent == expected_intent
    }) {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    tx.execute(
        "INSERT INTO taskrun_terminal_settlement_receipts(taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![input.taskrun_id.as_bytes(),input.assignment.fence.0 as i64,input.attempt_id.as_bytes(),node.as_bytes(),input.assignment.node_epoch as i64,event.as_bytes(),i64::try_from(version).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?],
    ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let changed = tx.execute(
        "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1 WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6 AND state='active' AND dispatch_intent=?7 AND release_event_id IS NULL",
        params![event.as_bytes(),input.taskrun_id.as_bytes(),input.assignment.fence.0 as i64,input.attempt_id.as_bytes(),node.as_bytes(),input.assignment.node_epoch as i64,expected_intent],
    ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if changed != 1 {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

pub(super) fn verify_released_occupation(
    tx: &rusqlite::Transaction<'_>,
    input: &D2ToolLoopFailureV1,
    event: EventId,
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let node = uuid::Uuid::parse_str(&input.assignment.node_id.0)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let released: Option<(Vec<u8>, String)> = tx.query_row(
        "SELECT release_event_id,dispatch_intent FROM taskrun_assignment_occupations
         WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5 AND state='released'",
        params![input.taskrun_id.as_bytes(),input.assignment.fence.0 as i64,input.attempt_id.as_bytes(),node.as_bytes(),input.assignment.node_epoch as i64],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let intent: Option<String> = tx
        .query_row(
            "SELECT state FROM taskrun_dispatch_intents
         WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5",
            params![
                input.taskrun_id.as_bytes(),
                input.assignment.fence.0 as i64,
                input.attempt_id.as_bytes(),
                node.as_bytes(),
                input.assignment.node_epoch as i64
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if released.as_ref().map(|saved| saved.0.as_slice()) != Some(event.as_bytes())
        || released.as_ref().map(|saved| saved.1.as_str())
            != Some(intent.as_deref().unwrap_or("absent"))
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    verify_settlement(
        tx,
        input,
        event,
        input.expected_taskrun_head,
        node.as_bytes(),
    )
}

fn verify_settlement(
    tx: &rusqlite::Transaction<'_>,
    input: &D2ToolLoopFailureV1,
    event: EventId,
    version: u64,
    node: &[u8],
) -> Result<(), CommitError> {
    use crate::store::parse_helpers::storage_failure;
    let exact: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5 AND terminal_event_id=?6 AND terminal_version=?7)",
        params![input.taskrun_id.as_bytes(),input.assignment.fence.0 as i64,input.attempt_id.as_bytes(),node,input.assignment.node_epoch as i64,event.as_bytes(),i64::try_from(version).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?],
        |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if exact {
        Ok(())
    } else {
        Err(storage_failure(StorageFailureKind::IntegrityViolation))
    }
}
